use std::net::IpAddr;
use std::path::Path;
use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, SystemTime};

use egui::{Align, Color32, CornerRadius, Layout, RichText, ScrollArea, Stroke, Vec2};
use pktscope_capture::{
    CaptureConfig, CaptureError, CaptureEvent, CaptureHandle, InterfaceInfo, LinuxLiveSource,
    PacketSource, PcapFileSource, PcapStreamSource, all_local_ips, list_interfaces,
};
use pktscope_core::{
    ConversationStats, Direction, IpStats, ParsedPacket, Protocol, TrafficFilter, TrafficStore,
    format_bytes, format_mac, format_rate, well_known_port_name,
};

use crate::cli::CliArgs;
use crate::widgets::{
    BG_ELEVATED, BG_SURFACE, BORDER_SUBTLE, COLOR_ACCENT, COLOR_ERROR, COLOR_INBOUND,
    COLOR_OUTBOUND, COLOR_TRANSIT, COLOR_WARNING, TEXT_MUTED, TEXT_PRIMARY, apply_theme,
    direction_color, draw_protocol_and_ports, draw_sent_recv_bar, draw_throughput_chart,
    format_clock_time, format_relative_time, protocol_color, scope_color,
};

const STORE_PACKET_CAPACITY: usize = 10_000;
const MAX_DRAIN_BATCH: usize = 2_000;
pub const SETCAP_COMMAND: &str =
    "sudo setcap cap_net_raw,cap_net_admin=eip $(which pktscope || echo ./target/release/pktscope)";

/// Active main view tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActiveTab {
    #[default]
    IpTalkers,
    Conversations,
    LivePackets,
}

/// Sortable columns for the IP Talkers table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IpSortColumn {
    Ip,
    SentBytes,
    RecvBytes,
    #[default]
    TotalBytes,
    Packets,
    Rate,
    LastSeen,
}

/// Sortable columns for the Conversations table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConvSortColumn {
    AddrA,
    AddrB,
    Protocol,
    BytesAToB,
    BytesBToA,
    #[default]
    TotalBytes,
    Rate,
    LastSeen,
}

/// Main `pktscope` desktop GUI application state.
pub struct PktScopeApp {
    pub store: TrafficStore,
    pub filter: TrafficFilter,
    pub port_input: String,
    pub interfaces: Vec<InterfaceInfo>,
    pub selected_interface: String,
    pub promiscuous: bool,
    pub pcap_path_input: String,
    pub capture_handle: Option<CaptureHandle>,
    pub capture_rx: Option<mpsc::Receiver<CaptureEvent>>,
    pub status_text: String,
    pub error_banner: Option<String>,
    pub permission_hint: Option<String>,
    pub active_tab: ActiveTab,
    pub ip_sort: (IpSortColumn, bool),
    pub conv_sort: (ConvSortColumn, bool),
    pub selected_ip: Option<IpAddr>,
    pub selected_packet_id: Option<u64>,
    pub auto_scroll: bool,
    pub is_live_capture: bool,
    pub paused: bool,
    theme_applied: bool,
}

impl Default for PktScopeApp {
    fn default() -> Self {
        Self::new_with_args(CliArgs::default())
    }
}

impl PktScopeApp {
    /// Creates a new [`PktScopeApp`] configured from parsed CLI options.
    pub fn new_with_args(args: CliArgs) -> Self {
        let interfaces = list_interfaces().unwrap_or_default();
        let mut store = TrafficStore::new(STORE_PACKET_CAPACITY);
        store.set_local_ips(all_local_ips());

        let selected_interface = args.interface.clone().unwrap_or_else(|| "any".to_string());
        let pcap_path_input = args
            .pcap_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();

        let mut app = Self {
            store,
            filter: TrafficFilter::default(),
            port_input: String::new(),
            interfaces,
            selected_interface,
            promiscuous: args.promiscuous,
            pcap_path_input,
            capture_handle: None,
            capture_rx: None,
            status_text: "Ready".to_string(),
            error_banner: None,
            permission_hint: None,
            active_tab: ActiveTab::IpTalkers,
            ip_sort: (IpSortColumn::TotalBytes, false),
            conv_sort: (ConvSortColumn::TotalBytes, false),
            selected_ip: None,
            selected_packet_id: None,
            auto_scroll: true,
            is_live_capture: false,
            paused: false,
            theme_applied: false,
        };

        if args.stdin {
            app.start_stdin_capture();
        } else if let Some(path) = &args.pcap_path {
            app.load_pcap_file(path);
        } else if let Some(iface) = &args.interface {
            app.start_live_capture(iface, args.promiscuous);
        }

        app
    }

    /// Refreshes host interfaces and local IP classification.
    pub fn refresh_interfaces(&mut self) {
        self.interfaces = list_interfaces().unwrap_or_default();
        self.store.set_local_ips(all_local_ips());
    }

    /// Stops any active capture source cleanly.
    pub fn stop_capture(&mut self) {
        if let Some(mut handle) = self.capture_handle.take() {
            handle.stop();
        }
        self.capture_rx = None;
        self.is_live_capture = false;
        self.paused = false;
        self.status_text = format!("Stopped ({} pkts)", self.store.total_packets());
    }

    /// Starts live capture on the selected interface (or `"any"`).
    pub fn start_live_capture(&mut self, interface: &str, promiscuous: bool) {
        self.stop_capture();
        self.error_banner = None;
        self.permission_hint = None;

        let iface_opt = if interface == "any" {
            None
        } else {
            Some(interface.to_string())
        };
        let cfg = CaptureConfig {
            interface: iface_opt,
            promiscuous,
            ..CaptureConfig::default()
        };

        match LinuxLiveSource::open(cfg) {
            Ok(source) => {
                let label = source.source_label();
                let (handle, rx) = CaptureHandle::start(source);
                self.capture_handle = Some(handle);
                self.capture_rx = Some(rx);
                self.is_live_capture = true;
                self.paused = false;
                self.status_text = format!("Live: {label}");
            }
            Err(CaptureError::PermissionDenied { hint, .. }) => {
                self.permission_hint = Some(hint);
                self.status_text = "Permission required".to_string();
            }
            Err(err) => {
                self.error_banner = Some(err.to_string());
                self.status_text = "Capture error".to_string();
            }
        }
    }

    /// Loads and replays a `.pcap` file into the store.
    pub fn load_pcap_file(&mut self, path: &Path) {
        self.stop_capture();
        self.error_banner = None;
        self.permission_hint = None;
        self.store.clear();
        self.selected_ip = None;
        self.selected_packet_id = None;

        match PcapFileSource::open(path, false) {
            Ok(source) => {
                let label = source.source_label();
                let (handle, rx) = CaptureHandle::start(source);
                self.capture_handle = Some(handle);
                self.capture_rx = Some(rx);
                self.is_live_capture = false;
                self.paused = false;
                self.status_text = format!("Loading {label}...");
            }
            Err(err) => {
                self.error_banner = Some(err.to_string());
                self.status_text = "PCAP load error".to_string();
            }
        }
    }

    /// Starts streaming `.pcap` packets from stdin.
    pub fn start_stdin_capture(&mut self) {
        self.stop_capture();
        self.error_banner = None;
        self.permission_hint = None;

        let source = PcapStreamSource::from_stdin();
        let (handle, rx) = CaptureHandle::start(source);
        self.capture_handle = Some(handle);
        self.capture_rx = Some(rx);
        self.is_live_capture = true;
        self.paused = false;
        self.status_text = "Stream: stdin".to_string();
    }

    /// Drains up to `max_batch` queued [`CaptureEvent`]s into [`TrafficStore`] and returns the count drained.
    pub fn drain_events(&mut self, max_batch: usize) -> usize {
        if self.paused {
            return 0;
        }
        let Some(rx) = self.capture_rx.as_ref() else {
            return 0;
        };

        let mut drained = 0usize;
        let mut finished = false;
        let mut err_msg: Option<String> = None;

        for _ in 0..max_batch {
            match rx.try_recv() {
                Ok(CaptureEvent::Packet(raw)) => {
                    self.store.ingest_raw(&raw);
                    drained += 1;
                }
                Ok(CaptureEvent::EndOfStream) => {
                    drained += 1;
                    finished = true;
                    break;
                }
                Ok(CaptureEvent::Error(msg)) => {
                    drained += 1;
                    err_msg = Some(msg);
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
            }
        }

        if let Some(msg) = err_msg {
            if let Some(mut handle) = self.capture_handle.take() {
                handle.stop();
            }
            self.capture_rx = None;
            self.is_live_capture = false;
            self.error_banner = Some(msg);
            self.status_text = "Capture error".to_string();
        } else if finished {
            let label = self
                .capture_handle
                .as_ref()
                .map(|h| h.source_label().to_string())
                .unwrap_or_else(|| "source".to_string());
            if let Some(mut handle) = self.capture_handle.take() {
                handle.stop();
            }
            self.capture_rx = None;
            self.is_live_capture = false;
            self.status_text = format!("Loaded {label} ({} pkts)", self.store.total_packets());
        }

        drained
    }

    /// Returns `true` when the capture channel is active and unpaused so the UI should keep polling.
    pub fn should_request_repaint(&self) -> bool {
        self.capture_rx.is_some() && !self.paused
    }

    fn schedule_repaint(&self, ctx: &egui::Context, drained: usize) {
        if self.should_request_repaint() {
            if drained >= MAX_DRAIN_BATCH {
                ctx.request_repaint();
            } else {
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
    }

    /// Returns the reference timestamp used for rolling rates, throughput charts, and "Last Seen" age.
    pub fn effective_reference_time(&self) -> SystemTime {
        if self.is_live_capture && !self.paused {
            match self.store.latest_timestamp() {
                Some(latest) => SystemTime::now().max(latest),
                None => SystemTime::now(),
            }
        } else {
            self.store.reference_time()
        }
    }

    /// Renders the complete UI. Callable from both `eframe::App::update` and headless tests.
    pub fn render_ui(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar_panel")
            .frame(
                egui::Frame::NONE
                    .fill(BG_SURFACE)
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .stroke(Stroke::new(1.0, BORDER_SUBTLE)),
            )
            .show(ctx, |ui| {
                self.render_toolbar(ui);
            });

        if self.permission_hint.is_some() || self.error_banner.is_some() {
            egui::TopBottomPanel::top("banners_panel")
                .frame(
                    egui::Frame::NONE
                        .fill(crate::widgets::BG_BASE)
                        .inner_margin(egui::Margin::symmetric(12, 6)),
                )
                .show(ctx, |ui| {
                    self.render_banners(ui, ctx);
                });
        }

        egui::TopBottomPanel::top("filter_panel")
            .frame(
                egui::Frame::NONE
                    .fill(BG_SURFACE)
                    .inner_margin(egui::Margin::symmetric(12, 6))
                    .stroke(Stroke::new(1.0, BORDER_SUBTLE)),
            )
            .show(ctx, |ui| {
                self.render_filter_bar(ui);
            });

        if self.active_tab == ActiveTab::LivePackets && self.selected_packet_id.is_some() {
            let selected = self.selected_packet_id.and_then(|id| {
                self.store
                    .recent_packets()
                    .iter()
                    .find(|p| p.id == id)
                    .cloned()
            });
            if let Some(pkt) = selected {
                egui::TopBottomPanel::bottom("packet_inspector_panel")
                    .resizable(true)
                    .min_height(130.0)
                    .default_height(175.0)
                    .frame(
                        egui::Frame::NONE
                            .fill(BG_SURFACE)
                            .inner_margin(egui::Margin::symmetric(12, 8))
                            .stroke(Stroke::new(1.0, BORDER_SUBTLE)),
                    )
                    .show(ctx, |ui| {
                        self.render_packet_inspector(ui, &pkt);
                    });
            }
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(crate::widgets::BG_BASE)
                    .inner_margin(egui::Margin::same(12)),
            )
            .show(ctx, |ui| {
                self.render_overview_strip(ui);
                ui.add_space(8.0);
                self.render_tab_bar(ui);
                ui.add_space(6.0);

                match self.active_tab {
                    ActiveTab::IpTalkers => self.render_ip_talkers_tab(ui),
                    ActiveTab::Conversations => self.render_conversations_tab(ui),
                    ActiveTab::LivePackets => self.render_live_packets_tab(ui),
                }
            });
    }

    fn render_toolbar(&mut self, ui: &mut egui::Ui) {
        let capturing = self.capture_handle.is_some();

        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("pktscope")
                    .size(15.0)
                    .strong()
                    .color(COLOR_INBOUND),
            );
            ui.separator();

            // Interface selector
            let current_iface_label =
                format_interface_label(&self.selected_interface, &self.interfaces);
            egui::ComboBox::from_id_salt("interface_combo")
                .selected_text(current_iface_label)
                .width(210.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.selected_interface,
                        "any".to_string(),
                        "any (all interfaces)",
                    );
                    for iface in &self.interfaces {
                        let label = format_interface_entry(iface);
                        ui.selectable_value(
                            &mut self.selected_interface,
                            iface.name.clone(),
                            label,
                        );
                    }
                });

            if ui
                .button("Refresh")
                .on_hover_text("Rescan network interfaces and local IPs")
                .clicked()
            {
                self.refresh_interfaces();
            }

            ui.checkbox(&mut self.promiscuous, "Promisc")
                .on_hover_text("Enable promiscuous mode (useful on SPAN / mirror ports)");

            if capturing {
                if ui
                    .button(RichText::new("Stop").color(COLOR_ERROR).strong())
                    .clicked()
                {
                    self.stop_capture();
                }
            } else if ui
                .button(RichText::new("Start").color(COLOR_TRANSIT).strong())
                .clicked()
            {
                let iface = self.selected_interface.clone();
                let promisc = self.promiscuous;
                self.start_live_capture(&iface, promisc);
            }

            let pause_label = if self.paused { "Resume" } else { "Pause" };
            if ui
                .add_enabled(capturing, egui::Button::new(pause_label))
                .clicked()
            {
                self.paused = !self.paused;
            }

            if ui.button("Clear").clicked() {
                self.store.clear();
                self.selected_ip = None;
                self.selected_packet_id = None;
            }

            ui.separator();

            ui.add(
                egui::TextEdit::singleline(&mut self.pcap_path_input)
                    .hint_text("path/to/capture.pcap")
                    .desired_width(180.0),
            );
            if ui.button("Load PCAP").clicked() {
                let trimmed = self.pcap_path_input.trim().to_string();
                if trimmed.is_empty() {
                    self.error_banner = Some("Enter a .pcap file path to load".to_string());
                } else {
                    self.load_pcap_file(Path::new(&trimmed));
                }
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (dot_color, badge_text) = if self.paused {
                    (COLOR_WARNING, format!("PAUSED | {}", self.status_text))
                } else if self.is_live_capture && capturing {
                    (COLOR_TRANSIT, self.status_text.clone())
                } else if capturing {
                    (COLOR_ACCENT, self.status_text.clone())
                } else {
                    (TEXT_MUTED, self.status_text.clone())
                };

                egui::Frame::NONE
                    .fill(BG_ELEVATED)
                    .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(8, 3))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (dot_rect, _) =
                                ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
                            ui.painter()
                                .circle_filled(dot_rect.center(), 4.0, dot_color);
                            ui.label(RichText::new(badge_text).size(11.5).color(TEXT_PRIMARY));
                        });
                    });
            });
        });
    }

    fn render_banners(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if let Some(hint) = self.permission_hint.clone() {
            egui::Frame::NONE
                .fill(Color32::from_rgba_unmultiplied(245, 158, 11, 22))
                .stroke(Stroke::new(1.0, COLOR_WARNING))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("Live Capture Permission Required:")
                                .strong()
                                .color(COLOR_WARNING),
                        );
                        ui.label(RichText::new(&hint).size(12.0).color(TEXT_PRIMARY));
                    });
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        egui::Frame::NONE
                            .fill(Color32::from_rgb(13, 17, 23))
                            .corner_radius(CornerRadius::same(4))
                            .inner_margin(egui::Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(SETCAP_COMMAND)
                                        .monospace()
                                        .size(11.5)
                                        .color(COLOR_INBOUND),
                                );
                            });
                        if ui.button("Copy Command").clicked() {
                            ctx.copy_text(SETCAP_COMMAND.to_string());
                        }
                        if ui.button("Dismiss").clicked() {
                            self.permission_hint = None;
                        }
                    });
                });
        }

        if let Some(err) = self.error_banner.clone() {
            egui::Frame::NONE
                .fill(Color32::from_rgba_unmultiplied(248, 113, 113, 22))
                .stroke(Stroke::new(1.0, COLOR_ERROR))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Error:").strong().color(COLOR_ERROR));
                        ui.label(RichText::new(&err).size(12.0).color(TEXT_PRIMARY));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button("Dismiss").clicked() {
                                self.error_banner = None;
                            }
                        });
                    });
                });
        }
    }

    fn render_filter_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Filter:").size(12.0).color(TEXT_MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.filter.ip_query)
                    .hint_text("IP / CIDR / Search (e.g. 192.168.1.0/24)")
                    .desired_width(230.0),
            );

            ui.label(RichText::new("Port:").size(12.0).color(TEXT_MUTED));
            let port_resp = ui.add(
                egui::TextEdit::singleline(&mut self.port_input)
                    .hint_text("Port")
                    .desired_width(64.0),
            );
            let trimmed_port = self.port_input.trim();
            if trimmed_port.is_empty() {
                self.filter.port = None;
            } else if let Ok(p) = trimmed_port.parse::<u16>() {
                self.filter.port = Some(p);
            } else {
                self.filter.port = None;
                port_resp.on_hover_text("Enter a valid port number (0-65535)");
            }

            ui.label(RichText::new("Proto:").size(12.0).color(TEXT_MUTED));
            let proto_label = self
                .filter
                .protocol
                .map_or_else(|| "All".to_string(), |p| p.name());
            egui::ComboBox::from_id_salt("filter_proto_combo")
                .selected_text(proto_label)
                .width(96.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.filter.protocol, None, "All");
                    ui.selectable_value(&mut self.filter.protocol, Some(Protocol::Tcp), "TCP");
                    ui.selectable_value(&mut self.filter.protocol, Some(Protocol::Udp), "UDP");
                    ui.selectable_value(&mut self.filter.protocol, Some(Protocol::Icmp), "ICMP");
                    ui.selectable_value(
                        &mut self.filter.protocol,
                        Some(Protocol::Icmpv6),
                        "ICMPv6",
                    );
                    ui.selectable_value(&mut self.filter.protocol, Some(Protocol::Arp), "ARP");
                });

            ui.label(RichText::new("Dir:").size(12.0).color(TEXT_MUTED));
            let dir_label = self
                .filter
                .direction
                .map_or_else(|| "All".to_string(), |d| d.to_string());
            egui::ComboBox::from_id_salt("filter_dir_combo")
                .selected_text(dir_label)
                .width(102.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.filter.direction, None, "All");
                    ui.selectable_value(
                        &mut self.filter.direction,
                        Some(Direction::Inbound),
                        "Inbound",
                    );
                    ui.selectable_value(
                        &mut self.filter.direction,
                        Some(Direction::Outbound),
                        "Outbound",
                    );
                    ui.selectable_value(
                        &mut self.filter.direction,
                        Some(Direction::Local),
                        "Local",
                    );
                    ui.selectable_value(
                        &mut self.filter.direction,
                        Some(Direction::Transit),
                        "Transit",
                    );
                });

            if (!self.filter.is_empty() || !self.port_input.is_empty())
                && ui.button("Clear Filters").clicked()
            {
                self.filter = TrafficFilter::default();
                self.port_input.clear();
            }
        });
    }

    fn render_overview_strip(&self, ui: &mut egui::Ui) {
        let ref_time = self.effective_reference_time();
        let (in_bps, out_bps, total_bps) = self.store.current_rates(ref_time);

        // 4 compact metric cards
        ui.columns(4, |cols| {
            render_metric_card(
                &mut cols[0],
                "Total Traffic",
                &format_bytes(self.store.total_bytes()),
                &format!(
                    "{} pkts ({})",
                    self.store.total_packets(),
                    format_rate(total_bps)
                ),
                TEXT_PRIMARY,
            );
            render_metric_card(
                &mut cols[1],
                "Inbound Rate",
                &format_rate(in_bps),
                "5s rolling avg",
                COLOR_INBOUND,
            );
            render_metric_card(
                &mut cols[2],
                "Outbound Rate",
                &format_rate(out_bps),
                "5s rolling avg",
                COLOR_OUTBOUND,
            );
            render_metric_card(
                &mut cols[3],
                "Active Entities",
                &format!(
                    "{} IPs / {} Convs",
                    self.store.ip_stats().count(),
                    self.store.conversations().count()
                ),
                &format!("{} buffered pkts", self.store.recent_packets().len()),
                COLOR_TRANSIT,
            );
        });

        ui.add_space(6.0);

        let samples = self.store.throughput_history(ref_time, 60);
        ui.columns(2, |cols| {
            egui::Frame::NONE
                .fill(BG_SURFACE)
                .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(egui::Margin::same(8))
                .show(&mut cols[0], |ui| {
                    draw_throughput_chart(ui, &samples);
                });

            egui::Frame::NONE
                .fill(BG_SURFACE)
                .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                .corner_radius(CornerRadius::same(6))
                .inner_margin(egui::Margin::same(8))
                .show(&mut cols[1], |ui| {
                    ui.set_min_height(128.0);
                    draw_protocol_and_ports(ui, &self.store);
                });
        });
    }

    fn render_tab_bar(&mut self, ui: &mut egui::Ui) {
        let ip_count = self.store.ip_stats().count();
        let conv_count = self.store.conversations().count();
        let pkt_count = self.store.recent_packets().len();

        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.active_tab,
                ActiveTab::IpTalkers,
                format!("IP Talkers ({ip_count})"),
            );
            ui.selectable_value(
                &mut self.active_tab,
                ActiveTab::Conversations,
                format!("Conversations ({conv_count})"),
            );
            ui.selectable_value(
                &mut self.active_tab,
                ActiveTab::LivePackets,
                format!("Live Packets ({pkt_count})"),
            );
        });
    }

    fn render_ip_talkers_tab(&mut self, ui: &mut egui::Ui) {
        let ref_time = self.effective_reference_time();
        let mut rows: Vec<&IpStats> = self
            .store
            .ip_stats()
            .filter(|s| {
                self.filter.matches_ip(s.ip)
                    && self
                        .filter
                        .protocol
                        .is_none_or(|proto| s.protocols.contains(&proto))
            })
            .collect();

        let (sort_col, asc) = self.ip_sort;
        rows.sort_by(|a, b| {
            let ord = match sort_col {
                IpSortColumn::Ip => a.ip.cmp(&b.ip),
                IpSortColumn::SentBytes => a.bytes_sent.cmp(&b.bytes_sent),
                IpSortColumn::RecvBytes => a.bytes_received.cmp(&b.bytes_received),
                IpSortColumn::TotalBytes => a.total_bytes().cmp(&b.total_bytes()),
                IpSortColumn::Packets => a.total_packets().cmp(&b.total_packets()),
                IpSortColumn::Rate => a
                    .rate_total_bps(ref_time)
                    .total_cmp(&b.rate_total_bps(ref_time)),
                IpSortColumn::LastSeen => a.last_seen.cmp(&b.last_seen),
            };
            let ordered = if asc { ord } else { ord.reverse() };
            ordered.then_with(|| a.ip.cmp(&b.ip))
        });

        let w_avail = ui.available_width();
        let w_ip = 144.0;
        let w_scope = 72.0;
        let w_sent = 114.0;
        let w_recv = 114.0;
        let w_bar = 76.0;
        let w_total = 74.0;
        let w_pkts = 60.0;
        let w_rate = 80.0;
        let w_seen = 64.0;
        let w_act = 54.0;
        let fixed = w_ip
            + w_scope
            + w_sent
            + w_recv
            + w_bar
            + w_total
            + w_pkts
            + w_rate
            + w_seen
            + w_act
            + 40.0;
        let w_protos = (w_avail - fixed).max(80.0);

        // Header
        egui::Frame::NONE
            .fill(BG_ELEVATED)
            .stroke(Stroke::new(1.0, BORDER_SUBTLE))
            .inner_margin(egui::Margin::symmetric(6, 4))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    sort_header(ui, "IP Address", IpSortColumn::Ip, &mut self.ip_sort, w_ip);
                    static_header(ui, "Scope", w_scope);
                    sort_header(
                        ui,
                        "Sent",
                        IpSortColumn::SentBytes,
                        &mut self.ip_sort,
                        w_sent,
                    );
                    sort_header(
                        ui,
                        "Recv",
                        IpSortColumn::RecvBytes,
                        &mut self.ip_sort,
                        w_recv,
                    );
                    static_header(ui, "S / R", w_bar);
                    sort_header(
                        ui,
                        "Total",
                        IpSortColumn::TotalBytes,
                        &mut self.ip_sort,
                        w_total,
                    );
                    sort_header(ui, "Pkts", IpSortColumn::Packets, &mut self.ip_sort, w_pkts);
                    sort_header(ui, "Rate", IpSortColumn::Rate, &mut self.ip_sort, w_rate);
                    static_header(ui, "Protocols", w_protos);
                    sort_header(
                        ui,
                        "Last Seen",
                        IpSortColumn::LastSeen,
                        &mut self.ip_sort,
                        w_seen,
                    );
                    static_header(ui, "Filter", w_act);
                });
            });

        if rows.is_empty() {
            ui.add_space(16.0);
            ui.label(
                RichText::new("No IP talkers match the current capture/filter.").color(TEXT_MUTED),
            );
            return;
        }

        let mut filter_to_apply: Option<String> = None;
        let row_height = 24.0;

        ScrollArea::vertical()
            .id_salt("ip_talkers_scroll")
            .auto_shrink([false, false])
            .show_rows(ui, row_height, rows.len(), |ui, range| {
                for idx in range {
                    let stat = rows[idx];
                    let selected = self.selected_ip == Some(stat.ip);
                    let row_bg = if selected {
                        Color32::from_rgba_unmultiplied(56, 189, 248, 30)
                    } else if idx % 2 == 1 {
                        Color32::from_rgb(18, 23, 30)
                    } else {
                        Color32::TRANSPARENT
                    };

                    egui::Frame::NONE
                        .fill(row_bg)
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.set_min_height(row_height - 4.0);
                            ui.horizontal(|ui| {
                                cell(ui, w_ip, |ui| {
                                    if ui
                                        .selectable_label(
                                            selected,
                                            RichText::new(stat.ip.to_string())
                                                .monospace()
                                                .size(12.0),
                                        )
                                        .clicked()
                                    {
                                        self.selected_ip = Some(stat.ip);
                                    }
                                });
                                cell(ui, w_scope, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(stat.scope.to_string())
                                            .size(11.0)
                                            .color(scope_color(stat.scope)),
                                    );
                                });
                                cell(ui, w_sent, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format!(
                                            "{} ({})",
                                            format_bytes(stat.bytes_sent),
                                            stat.packets_sent
                                        ))
                                        .size(11.5)
                                        .color(COLOR_OUTBOUND),
                                    );
                                });
                                cell(ui, w_recv, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format!(
                                            "{} ({})",
                                            format_bytes(stat.bytes_received),
                                            stat.packets_received
                                        ))
                                        .size(11.5)
                                        .color(COLOR_INBOUND),
                                    );
                                });
                                cell(ui, w_bar, |ui| {
                                    draw_sent_recv_bar(ui, stat.bytes_sent, stat.bytes_received);
                                });
                                cell(ui, w_total, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format_bytes(stat.total_bytes()))
                                            .size(11.5)
                                            .strong(),
                                    );
                                });
                                cell(ui, w_pkts, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(stat.total_packets().to_string())
                                            .size(11.5)
                                            .monospace(),
                                    );
                                });
                                cell(ui, w_rate, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format_rate(stat.rate_total_bps(ref_time)))
                                            .size(11.5)
                                            .color(TEXT_PRIMARY),
                                    );
                                });
                                cell(ui, w_protos, |ui| {
                                    let protos = stat
                                        .protocols
                                        .iter()
                                        .map(Protocol::name)
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    cell_label(
                                        ui,
                                        RichText::new(protos).size(11.0).color(TEXT_MUTED),
                                    );
                                });
                                cell(ui, w_seen, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format_relative_time(
                                            stat.last_seen,
                                            ref_time,
                                        ))
                                        .size(11.0)
                                        .color(TEXT_MUTED),
                                    );
                                });
                                cell(ui, w_act, |ui| {
                                    if ui.small_button("Filter").clicked() {
                                        filter_to_apply = Some(stat.ip.to_string());
                                    }
                                });
                            });
                        });
                }
            });

        if let Some(ip_str) = filter_to_apply {
            self.filter.ip_query = ip_str;
        }
    }

    fn render_conversations_tab(&mut self, ui: &mut egui::Ui) {
        let ref_time = self.effective_reference_time();
        let mut rows: Vec<&ConversationStats> = self
            .store
            .conversations()
            .filter(|c| {
                let ip_ok = self.filter.ip_query.trim().is_empty()
                    || self.filter.matches_ip(c.key.addr_a)
                    || self.filter.matches_ip(c.key.addr_b);
                let proto_ok = self.filter.protocol.is_none_or(|p| c.key.protocol == p);
                let port_ok = self.filter.port.is_none_or(|p| c.ports.contains(&p));
                ip_ok && proto_ok && port_ok
            })
            .collect();

        let (sort_col, asc) = self.conv_sort;
        rows.sort_by(|a, b| {
            let ord = match sort_col {
                ConvSortColumn::AddrA => a.key.addr_a.cmp(&b.key.addr_a),
                ConvSortColumn::AddrB => a.key.addr_b.cmp(&b.key.addr_b),
                ConvSortColumn::Protocol => a.key.protocol.cmp(&b.key.protocol),
                ConvSortColumn::BytesAToB => a.bytes_a_to_b.cmp(&b.bytes_a_to_b),
                ConvSortColumn::BytesBToA => a.bytes_b_to_a.cmp(&b.bytes_b_to_a),
                ConvSortColumn::TotalBytes => a.total_bytes().cmp(&b.total_bytes()),
                ConvSortColumn::Rate => a.rate_bps(ref_time).total_cmp(&b.rate_bps(ref_time)),
                ConvSortColumn::LastSeen => a.last_seen.cmp(&b.last_seen),
            };
            let ordered = if asc { ord } else { ord.reverse() };
            ordered.then_with(|| a.key.cmp(&b.key))
        });

        let w_avail = ui.available_width();
        let w_a = 144.0;
        let w_b = 144.0;
        let w_proto = 58.0;
        let w_ab = 82.0;
        let w_ba = 82.0;
        let w_total = 78.0;
        let w_rate = 82.0;
        let w_seen = 68.0;
        let w_act = 58.0;
        let fixed = w_a + w_b + w_proto + w_ab + w_ba + w_total + w_rate + w_seen + w_act + 36.0;
        let w_ports = (w_avail - fixed).max(95.0);

        egui::Frame::NONE
            .fill(BG_ELEVATED)
            .stroke(Stroke::new(1.0, BORDER_SUBTLE))
            .inner_margin(egui::Margin::symmetric(6, 4))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    sort_header(
                        ui,
                        "Endpoint A",
                        ConvSortColumn::AddrA,
                        &mut self.conv_sort,
                        w_a,
                    );
                    sort_header(
                        ui,
                        "Endpoint B",
                        ConvSortColumn::AddrB,
                        &mut self.conv_sort,
                        w_b,
                    );
                    sort_header(
                        ui,
                        "Proto",
                        ConvSortColumn::Protocol,
                        &mut self.conv_sort,
                        w_proto,
                    );
                    static_header(ui, "Ports", w_ports);
                    sort_header(
                        ui,
                        "A -> B",
                        ConvSortColumn::BytesAToB,
                        &mut self.conv_sort,
                        w_ab,
                    );
                    sort_header(
                        ui,
                        "B -> A",
                        ConvSortColumn::BytesBToA,
                        &mut self.conv_sort,
                        w_ba,
                    );
                    sort_header(
                        ui,
                        "Total",
                        ConvSortColumn::TotalBytes,
                        &mut self.conv_sort,
                        w_total,
                    );
                    sort_header(
                        ui,
                        "Rate",
                        ConvSortColumn::Rate,
                        &mut self.conv_sort,
                        w_rate,
                    );
                    sort_header(
                        ui,
                        "Last Seen",
                        ConvSortColumn::LastSeen,
                        &mut self.conv_sort,
                        w_seen,
                    );
                    static_header(ui, "Filter", w_act);
                });
            });

        if rows.is_empty() {
            ui.add_space(16.0);
            ui.label(
                RichText::new("No conversations match the current capture/filter.")
                    .color(TEXT_MUTED),
            );
            return;
        }

        let mut filter_to_apply: Option<String> = None;
        let row_height = 24.0;

        ScrollArea::vertical()
            .id_salt("convs_scroll")
            .auto_shrink([false, false])
            .show_rows(ui, row_height, rows.len(), |ui, range| {
                for idx in range {
                    let conv = rows[idx];
                    let row_bg = if idx % 2 == 1 {
                        Color32::from_rgb(18, 23, 30)
                    } else {
                        Color32::TRANSPARENT
                    };

                    egui::Frame::NONE
                        .fill(row_bg)
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.set_min_height(row_height - 4.0);
                            ui.horizontal(|ui| {
                                cell(ui, w_a, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(conv.key.addr_a.to_string())
                                            .monospace()
                                            .size(11.5),
                                    );
                                });
                                cell(ui, w_b, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(conv.key.addr_b.to_string())
                                            .monospace()
                                            .size(11.5),
                                    );
                                });
                                cell(ui, w_proto, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(conv.key.protocol.name())
                                            .size(11.5)
                                            .color(protocol_color(conv.key.protocol)),
                                    );
                                });
                                cell(ui, w_ports, |ui| {
                                    let ports_str = format_conv_ports(conv);
                                    cell_label(
                                        ui,
                                        RichText::new(ports_str).size(11.0).color(TEXT_MUTED),
                                    );
                                });
                                cell(ui, w_ab, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format_bytes(conv.bytes_a_to_b)).size(11.5),
                                    );
                                });
                                cell(ui, w_ba, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format_bytes(conv.bytes_b_to_a)).size(11.5),
                                    );
                                });
                                cell(ui, w_total, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format_bytes(conv.total_bytes()))
                                            .size(11.5)
                                            .strong(),
                                    );
                                });
                                cell(ui, w_rate, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format_rate(conv.rate_bps(ref_time)))
                                            .size(11.5),
                                    );
                                });
                                cell(ui, w_seen, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format_relative_time(
                                            conv.last_seen,
                                            ref_time,
                                        ))
                                        .size(11.0)
                                        .color(TEXT_MUTED),
                                    );
                                });
                                cell(ui, w_act, |ui| {
                                    if ui.small_button("Filter").clicked() {
                                        filter_to_apply = Some(conv.key.addr_a.to_string());
                                    }
                                });
                            });
                        });
                }
            });

        if let Some(ip_str) = filter_to_apply {
            self.filter.ip_query = ip_str;
        }
    }

    fn render_live_packets_tab(&mut self, ui: &mut egui::Ui) {
        let filtered: Vec<&ParsedPacket> = self
            .store
            .recent_packets()
            .iter()
            .filter(|pkt| self.filter.matches_packet(pkt))
            .collect();

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.auto_scroll, "Auto-scroll");
            ui.separator();
            ui.label(
                RichText::new(format!(
                    "Showing {} of {} buffered packets",
                    filtered.len(),
                    self.store.recent_packets().len()
                ))
                .size(11.5)
                .color(TEXT_MUTED),
            );
        });
        ui.add_space(4.0);

        let w_avail = ui.available_width();
        let w_id = 54.0;
        let w_time = 92.0;
        let w_dir = 68.0;
        let w_src = 164.0;
        let w_dst = 164.0;
        let w_proto = 58.0;
        let w_len = 54.0;
        let fixed = w_id + w_time + w_dir + w_src + w_dst + w_proto + w_len + 32.0;
        let w_info = (w_avail - fixed).max(140.0);

        egui::Frame::NONE
            .fill(BG_ELEVATED)
            .stroke(Stroke::new(1.0, BORDER_SUBTLE))
            .inner_margin(egui::Margin::symmetric(6, 4))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    static_header(ui, "#", w_id);
                    static_header(ui, "Time (UTC)", w_time);
                    static_header(ui, "Dir", w_dir);
                    static_header(ui, "Source", w_src);
                    static_header(ui, "Destination", w_dst);
                    static_header(ui, "Proto", w_proto);
                    static_header(ui, "Len", w_len);
                    static_header(ui, "Info", w_info);
                });
            });

        if filtered.is_empty() {
            ui.add_space(16.0);
            ui.label(
                RichText::new("No packets match the current capture/filter.").color(TEXT_MUTED),
            );
            return;
        }

        let row_height = 22.0;
        let mut clicked_id: Option<u64> = None;

        ScrollArea::vertical()
            .id_salt("live_packets_scroll")
            .stick_to_bottom(self.auto_scroll)
            .auto_shrink([false, false])
            .show_rows(ui, row_height, filtered.len(), |ui, range| {
                for idx in range {
                    let pkt = filtered[idx];
                    let selected = self.selected_packet_id == Some(pkt.id);
                    let row_bg = if selected {
                        Color32::from_rgba_unmultiplied(56, 189, 248, 36)
                    } else if idx % 2 == 1 {
                        Color32::from_rgb(18, 23, 30)
                    } else {
                        Color32::TRANSPARENT
                    };

                    egui::Frame::NONE
                        .fill(row_bg)
                        .inner_margin(egui::Margin::symmetric(6, 1))
                        .show(ui, |ui| {
                            ui.set_min_height(row_height - 2.0);
                            ui.horizontal(|ui| {
                                cell(ui, w_id, |ui| {
                                    if ui
                                        .selectable_label(
                                            selected,
                                            RichText::new(pkt.id.to_string())
                                                .monospace()
                                                .size(11.0),
                                        )
                                        .clicked()
                                    {
                                        clicked_id = Some(pkt.id);
                                    }
                                });
                                cell(ui, w_time, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(format_clock_time(pkt.timestamp))
                                            .monospace()
                                            .size(11.0)
                                            .color(TEXT_MUTED),
                                    );
                                });
                                cell(ui, w_dir, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(pkt.direction.to_string())
                                            .size(11.0)
                                            .color(direction_color(pkt.direction)),
                                    );
                                });
                                cell(ui, w_src, |ui| {
                                    let s = format_endpoint(pkt.src_ip, pkt.src_port, pkt.src_mac);
                                    cell_label(ui, RichText::new(s).monospace().size(11.0));
                                });
                                cell(ui, w_dst, |ui| {
                                    let d = format_endpoint(pkt.dst_ip, pkt.dst_port, pkt.dst_mac);
                                    cell_label(ui, RichText::new(d).monospace().size(11.0));
                                });
                                cell(ui, w_proto, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(pkt.protocol.name())
                                            .size(11.0)
                                            .color(protocol_color(pkt.protocol)),
                                    );
                                });
                                cell(ui, w_len, |ui| {
                                    cell_label(
                                        ui,
                                        RichText::new(pkt.original_len.to_string())
                                            .monospace()
                                            .size(11.0),
                                    );
                                });
                                cell(ui, w_info, |ui| {
                                    if ui
                                        .selectable_label(
                                            selected,
                                            RichText::new(&pkt.info).size(11.5),
                                        )
                                        .clicked()
                                    {
                                        clicked_id = Some(pkt.id);
                                    }
                                });
                            });
                        });
                }
            });

        if let Some(id) = clicked_id {
            self.selected_packet_id = Some(id);
        }
    }

    fn render_packet_inspector(&mut self, ui: &mut egui::Ui, pkt: &ParsedPacket) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!(
                    "Packet #{}  |  UTC {}  |  {}",
                    pkt.id,
                    format_clock_time(pkt.timestamp),
                    pkt.info
                ))
                .strong()
                .color(COLOR_INBOUND),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("Close").clicked() {
                    self.selected_packet_id = None;
                }
            });
        });
        ui.separator();

        ScrollArea::vertical()
            .id_salt("packet_inspector_scroll")
            .show(ui, |ui| {
                ui.columns(3, |cols| {
                    // L2
                    cols[0].label(RichText::new("L2 Link Layer").strong().size(12.0));
                    cols[0].label(format!("Link Type: {}", pkt.link_type));
                    cols[0].label(format!(
                        "Src MAC: {}",
                        pkt.src_mac.map_or_else(|| "-".into(), format_mac)
                    ));
                    cols[0].label(format!(
                        "Dst MAC: {}",
                        pkt.dst_mac.map_or_else(|| "-".into(), format_mac)
                    ));
                    cols[0].label(format!(
                        "VLAN ID: {}",
                        pkt.vlan_id.map_or_else(|| "-".into(), |v| v.to_string())
                    ));

                    // L3
                    cols[1].label(RichText::new("L3 Network Layer").strong().size(12.0));
                    cols[1].label(format!(
                        "Src IP: {}",
                        pkt.src_ip.map_or_else(|| "-".into(), |ip| ip.to_string())
                    ));
                    cols[1].label(format!(
                        "Dst IP: {}",
                        pkt.dst_ip.map_or_else(|| "-".into(), |ip| ip.to_string())
                    ));
                    cols[1].label(format!(
                        "TTL / Hop Limit: {}",
                        pkt.ttl.map_or_else(|| "-".into(), |t| t.to_string())
                    ));
                    cols[1].colored_label(
                        direction_color(pkt.direction),
                        format!("Direction: {}", pkt.direction),
                    );
                    if let Some(arp) = &pkt.arp {
                        cols[1].label(format!(
                            "ARP op={}: {} ({}) -> {} ({})",
                            arp.opcode,
                            arp.sender_ip,
                            format_mac(arp.sender_mac),
                            arp.target_ip,
                            format_mac(arp.target_mac)
                        ));
                    }

                    // L4
                    cols[2].label(RichText::new("L4 Transport & Sizes").strong().size(12.0));
                    cols[2].colored_label(
                        protocol_color(pkt.protocol),
                        format!("Protocol: {}", pkt.protocol.name()),
                    );
                    cols[2].label(format!("Src Port: {}", format_port_detail(pkt.src_port)));
                    cols[2].label(format!("Dst Port: {}", format_port_detail(pkt.dst_port)));
                    if let Some(flags) = &pkt.tcp_flags {
                        let s = flags.format_short();
                        cols[2].label(format!(
                            "TCP Flags: {}",
                            if s.is_empty() { "-" } else { &s }
                        ));
                    }
                    if let Some(icmp) = &pkt.icmp_summary {
                        cols[2].label(format!("ICMP: {icmp}"));
                    }
                    cols[2].label(format!(
                        "Length: {} B wire / {} B captured",
                        pkt.original_len, pkt.captured_len
                    ));
                });
            });
    }
}

impl eframe::App for PktScopeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            apply_theme(ctx);
            self.theme_applied = true;
        }
        let drained = self.drain_events(MAX_DRAIN_BATCH);
        self.render_ui(ctx);
        self.schedule_repaint(ctx, drained);
    }
}

fn render_metric_card(
    ui: &mut egui::Ui,
    title: &str,
    value: &str,
    subtitle: &str,
    value_color: Color32,
) {
    egui::Frame::NONE
        .fill(BG_SURFACE)
        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(RichText::new(title).size(11.0).color(TEXT_MUTED));
            ui.label(RichText::new(value).size(16.0).strong().color(value_color));
            ui.label(RichText::new(subtitle).size(10.5).color(TEXT_MUTED));
        });
}

fn static_header(ui: &mut egui::Ui, label: &str, width: f32) {
    cell(ui, width, |ui| {
        cell_label(
            ui,
            RichText::new(label).size(11.5).strong().color(TEXT_MUTED),
        );
    });
}

fn sort_header<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    label: &str,
    col: T,
    sort_state: &mut (T, bool),
    width: f32,
) {
    let active = sort_state.0 == col;
    let text = if active {
        let arrow = if sort_state.1 { "▲" } else { "▼" };
        format!("{label} {arrow}")
    } else {
        label.to_string()
    };
    cell(ui, width, |ui| {
        let rt = RichText::new(text).size(11.5).strong().color(if active {
            COLOR_INBOUND
        } else {
            TEXT_MUTED
        });
        if ui.add(egui::Button::new(rt).frame(false)).clicked() {
            if active {
                sort_state.1 = !sort_state.1;
            } else {
                sort_state.0 = col;
                sort_state.1 = false;
            }
        }
    });
}

fn cell(ui: &mut egui::Ui, width: f32, add_contents: impl FnOnce(&mut egui::Ui)) {
    ui.allocate_ui_with_layout(
        Vec2::new(width, 20.0),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.set_max_width(width);
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
            add_contents(ui);
        },
    );
}

fn cell_label(ui: &mut egui::Ui, text: impl Into<egui::WidgetText>) {
    ui.add(egui::Label::new(text).truncate());
}

fn format_interface_label(selected: &str, interfaces: &[InterfaceInfo]) -> String {
    if selected == "any" {
        return "any (all interfaces)".to_string();
    }
    if let Some(info) = interfaces.iter().find(|i| i.name == selected) {
        return format_interface_entry(info);
    }
    selected.to_string()
}

fn format_interface_entry(info: &InterfaceInfo) -> String {
    let state = if info.is_up { "UP" } else { "DOWN" };
    match info.ips.first() {
        Some(ip) => format!("{} [{state}] {ip}", info.name),
        None => format!("{} [{state}]", info.name),
    }
}

fn format_endpoint(ip: Option<IpAddr>, port: Option<u16>, mac: Option<[u8; 6]>) -> String {
    match (ip, port) {
        (Some(addr), Some(p)) => format!("{addr}:{p}"),
        (Some(addr), None) => addr.to_string(),
        (None, _) => mac.map_or_else(|| "-".to_string(), format_mac),
    }
}

fn format_port_detail(port: Option<u16>) -> String {
    match port {
        Some(p) => match well_known_port_name(p) {
            Some(svc) => format!("{p} ({svc})"),
            None => p.to_string(),
        },
        None => "-".to_string(),
    }
}

fn format_conv_ports(conv: &ConversationStats) -> String {
    if conv.ports.is_empty() {
        return "-".to_string();
    }
    let mut items = Vec::new();
    for &p in conv.ports.iter().take(4) {
        match well_known_port_name(p) {
            Some(svc) => items.push(format!("{p}/{svc}")),
            None => items.push(p.to_string()),
        }
    }
    if conv.ports.len() > 4 {
        items.push(format!("+{}", conv.ports.len() - 4));
    }
    items.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pktscope_core::{LinkType, RawPacket};
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_tcp_packet(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        sec: u64,
    ) -> RawPacket {
        let payload = [0x55u8; 16];
        let total_ip_len = (20 + 20 + payload.len()) as u16;
        let mut data = Vec::with_capacity(14 + total_ip_len as usize);
        // Ethernet header
        data.extend_from_slice(&[0x11; 6]);
        data.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        data.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4 header
        data.extend_from_slice(&[0x45, 0x00]);
        data.extend_from_slice(&total_ip_len.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 6, 0x00, 0x00]);
        data.extend_from_slice(&src);
        data.extend_from_slice(&dst);
        // TCP header (SYN+ACK = 0x12)
        data.extend_from_slice(&sport.to_be_bytes());
        data.extend_from_slice(&dport.to_be_bytes());
        data.extend_from_slice(&10u32.to_be_bytes());
        data.extend_from_slice(&20u32.to_be_bytes());
        data.extend_from_slice(&[0x50, 0x12]);
        data.extend_from_slice(&4096u16.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&payload);

        let len = data.len() as u32;
        RawPacket {
            timestamp: UNIX_EPOCH + Duration::from_secs(sec),
            captured_len: len,
            original_len: len,
            link_type: LinkType::Ethernet,
            data,
        }
    }

    #[test]
    fn headless_render_ui_all_tabs_filters_and_permission_banner() {
        let mut app = PktScopeApp::new_with_args(CliArgs::default());
        let mut locals = HashSet::new();
        locals.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        app.store.set_local_ips(locals);

        let p1 = app.store.ingest_raw(&sample_tcp_packet(
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            52000,
            443,
            1_700_000_000,
        ));
        let p1_id = p1.id;
        app.store.ingest_raw(&sample_tcp_packet(
            [93, 184, 216, 34],
            [192, 168, 1, 10],
            443,
            52000,
            1_700_000_001,
        ));
        app.store.ingest_raw(&sample_tcp_packet(
            [10, 0, 0, 5],
            [8, 8, 8, 8],
            40000,
            53,
            1_700_000_002,
        ));

        app.permission_hint = Some("Live capture requires CAP_NET_RAW".to_string());
        app.error_banner = Some("Sample error banner".to_string());
        app.filter.ip_query = "192.168.1.0/24".to_string();
        app.filter.protocol = Some(Protocol::Tcp);
        app.port_input = "443".to_string();
        app.selected_packet_id = Some(p1_id);

        let ctx = egui::Context::default();
        apply_theme(&ctx);

        for tab in [
            ActiveTab::IpTalkers,
            ActiveTab::Conversations,
            ActiveTab::LivePackets,
        ] {
            app.active_tab = tab;
            let output = ctx.run(egui::RawInput::default(), |ctx| {
                app.render_ui(ctx);
            });
            assert!(
                !output.shapes.is_empty(),
                "expected rendered shapes for {tab:?}"
            );
        }

        // Also verify clearing filters works with no panic on empty/non-matching view
        app.filter.ip_query = "203.0.113.0/24".to_string();
        app.active_tab = ActiveTab::IpTalkers;
        let empty_out = ctx.run(egui::RawInput::default(), |ctx| {
            app.render_ui(ctx);
        });
        assert!(!empty_out.shapes.is_empty());

        let _ = SystemTime::UNIX_EPOCH;
    }

    #[test]
    fn drain_events_respects_pause_handles_eos_and_errors() {
        let mut app = PktScopeApp::new_with_args(CliArgs::default());
        let (tx, rx) = mpsc::channel();
        app.capture_rx = Some(rx);
        app.is_live_capture = true;

        let pkt = sample_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1_700_000_010);
        tx.send(CaptureEvent::Packet(pkt.clone())).unwrap();

        // While paused, drain_events must not consume queued packets
        app.paused = true;
        app.drain_events(100);
        assert_eq!(app.store.total_packets(), 0);

        // Unpause -> packet ingested
        app.paused = false;
        app.drain_events(100);
        assert_eq!(app.store.total_packets(), 1);

        // Error event clears capture state and sets error_banner
        tx.send(CaptureEvent::Error("boom".to_string())).unwrap();
        app.drain_events(100);
        assert_eq!(app.error_banner.as_deref(), Some("boom"));
        assert!(!app.is_live_capture);
        assert!(app.capture_rx.is_none());

        // EndOfStream marks stream finished cleanly
        let (tx2, rx2) = mpsc::channel();
        app.capture_rx = Some(rx2);
        app.is_live_capture = true;
        tx2.send(CaptureEvent::Packet(pkt)).unwrap();
        tx2.send(CaptureEvent::EndOfStream).unwrap();
        app.drain_events(100);
        assert_eq!(app.store.total_packets(), 2);
        assert!(!app.is_live_capture);
        assert!(app.capture_rx.is_none());
    }

    #[test]
    fn drain_events_continues_past_max_batch_after_producer_exits() {
        use pktscope_capture::NextPacket;

        struct BurstSource {
            remaining: usize,
            pkt: RawPacket,
        }

        impl PacketSource for BurstSource {
            fn next_packet(&mut self) -> Result<NextPacket, CaptureError> {
                if self.remaining == 0 {
                    Ok(NextPacket::Eof)
                } else {
                    self.remaining -= 1;
                    Ok(NextPacket::Packet(self.pkt.clone()))
                }
            }

            fn source_label(&self) -> String {
                "burst-pcap".to_string()
            }
        }

        let total_pkts = MAX_DRAIN_BATCH + 500;
        let pkt = sample_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1_700_000_010);
        let (handle, rx) = CaptureHandle::start(BurstSource {
            remaining: total_pkts,
            pkt,
        });

        // Wait until the producer thread has pushed all 2,500 packets + EndOfStream and exited.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while handle.is_running() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !handle.is_running(),
            "burst producer should exit before UI drains"
        );

        let mut app = PktScopeApp::new_with_args(CliArgs::default());
        app.capture_handle = Some(handle);
        app.capture_rx = Some(rx);
        app.is_live_capture = false;

        let ctx = egui::Context::default();
        apply_theme(&ctx);

        // First frame drains MAX_DRAIN_BATCH packets and schedules an immediate repaint.
        let out1 = ctx.run(egui::RawInput::default(), |ctx| {
            let drained = app.drain_events(MAX_DRAIN_BATCH);
            assert_eq!(drained, MAX_DRAIN_BATCH);
            assert_eq!(app.store.total_packets(), MAX_DRAIN_BATCH as u64);
            assert!(app.should_request_repaint());
            app.render_ui(ctx);
            app.schedule_repaint(ctx, drained);
        });
        assert_eq!(
            out1.viewport_output[&egui::ViewportId::ROOT].repaint_delay,
            Duration::ZERO
        );
        assert!(app.capture_rx.is_some());

        // Second frame drains remaining 500 packets + EndOfStream even though producer already exited.
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            let drained = app.drain_events(MAX_DRAIN_BATCH);
            assert_eq!(drained, 501);
            assert_eq!(app.store.total_packets(), total_pkts as u64);
            assert!(app.capture_rx.is_none());
            assert!(!app.should_request_repaint());
            app.render_ui(ctx);
            app.schedule_repaint(ctx, drained);
        });
        assert!(app.status_text.contains("2500 pkts"));

        // Verify schedule_repaint does not schedule another repaint once capture_rx is None.
        let settled_ctx = egui::Context::default();
        let _ = settled_ctx.run(egui::RawInput::default(), |_| {});
        let _ = settled_ctx.run(egui::RawInput::default(), |_| {});
        let out_idle = settled_ctx.run(egui::RawInput::default(), |ctx| {
            app.schedule_repaint(ctx, 0);
        });
        assert!(
            out_idle.viewport_output[&egui::ViewportId::ROOT].repaint_delay
                > Duration::from_secs(1)
        );
    }

    #[test]
    fn effective_reference_time_advances_only_when_live_and_unpaused() {
        let mut app = PktScopeApp::new_with_args(CliArgs::default());
        let old_sec = 1_700_000_000;
        let old_ts = UNIX_EPOCH + Duration::from_secs(old_sec);
        app.store.ingest_raw(&sample_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            old_sec,
        ));

        // Static PCAP mode uses the latest packet timestamp.
        app.is_live_capture = false;
        app.paused = false;
        assert_eq!(app.effective_reference_time(), old_ts);

        // Paused live capture freezes at latest packet timestamp.
        app.is_live_capture = true;
        app.paused = true;
        assert_eq!(app.effective_reference_time(), old_ts);

        // Unpaused live capture advances with wall clock so idle rates/Last Seen decay.
        app.paused = false;
        let before = SystemTime::now();
        let live_ref = app.effective_reference_time();
        assert!(live_ref >= before);
        assert!(live_ref > old_ts);

        // If latest packet timestamp is ahead of wall clock, clamp to latest timestamp.
        let future_ts = SystemTime::now() + Duration::from_secs(3600);
        let mut future_pkt = sample_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, old_sec);
        future_pkt.timestamp = future_ts;
        app.store.ingest_raw(&future_pkt);
        assert_eq!(app.effective_reference_time(), future_ts);
    }

    #[test]
    fn long_ipv6_table_cells_truncate_without_expanding_column_width() {
        use std::net::Ipv6Addr;

        let mut app = PktScopeApp::new_with_args(CliArgs::default());
        let src_v6: Ipv6Addr = "2001:0db8:85a3:0001:0002:8a2e:0370:7334".parse().unwrap();
        let dst_v6: Ipv6Addr = "fe80:0000:0000:0000:0202:b3ff:fe1e:8329".parse().unwrap();

        // Build an Ethernet + IPv6 + TCP packet.
        let mut data = Vec::new();
        data.extend_from_slice(&[0x11; 6]);
        data.extend_from_slice(&[0x22; 6]);
        data.extend_from_slice(&0x86ddu16.to_be_bytes());
        // IPv6 header (40 bytes) + TCP header (20 bytes)
        data.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&20u16.to_be_bytes());
        data.push(6); // TCP
        data.push(64);
        data.extend_from_slice(&src_v6.octets());
        data.extend_from_slice(&dst_v6.octets());
        data.extend_from_slice(&54321u16.to_be_bytes());
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&[0x50, 0x02]);
        data.extend_from_slice(&4096u16.to_be_bytes());
        data.extend_from_slice(&[0u8; 4]);

        let len = data.len() as u32;
        app.store.ingest_raw(&RawPacket {
            timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            captured_len: len,
            original_len: len,
            link_type: LinkType::Ethernet,
            data,
        });

        let ctx = egui::Context::default();
        apply_theme(&ctx);

        // Verify cell() + cell_label() / selectable_label keep column width bounded.
        let col_w = 144.0_f32;
        let long_text = format!("{src_v6}:54321");
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let start_x = ui.cursor().min.x;
                    cell(ui, col_w, |ui| {
                        cell_label(ui, RichText::new(&long_text).monospace().size(12.0));
                    });
                    let after_label_x = ui.cursor().min.x;
                    assert!(
                        after_label_x <= start_x + col_w + ui.spacing().item_spacing.x + 1.0,
                        "cell_label pushed next column: start={start_x}, after={after_label_x}"
                    );

                    cell(ui, col_w, |ui| {
                        let _ = ui.selectable_label(
                            false,
                            RichText::new(&long_text).monospace().size(12.0),
                        );
                    });
                    let after_sel_x = ui.cursor().min.x;
                    assert!(
                        after_sel_x <= after_label_x + col_w + ui.spacing().item_spacing.x + 1.0,
                        "selectable_label pushed next column: before={after_label_x}, after={after_sel_x}"
                    );
                });
            });
        });

        // Also render all three tabs with long IPv6 addresses to confirm no layout panic.
        for tab in [
            ActiveTab::IpTalkers,
            ActiveTab::Conversations,
            ActiveTab::LivePackets,
        ] {
            app.active_tab = tab;
            let out = ctx.run(egui::RawInput::default(), |ctx| {
                app.render_ui(ctx);
            });
            assert!(!out.shapes.is_empty());
        }
    }
}
