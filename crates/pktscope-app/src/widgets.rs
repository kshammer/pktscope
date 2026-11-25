use std::time::{Duration, SystemTime, UNIX_EPOCH};

use egui::{Align2, Color32, CornerRadius, FontId, Mesh, Pos2, Rect, Sense, Stroke, Vec2, epaint};
use pktscope_core::{
    Direction, IpScope, Protocol, ThroughputSample, TrafficStore, format_bytes, format_rate,
    well_known_port_name,
};

// Observability dark palette
pub const BG_BASE: Color32 = Color32::from_rgb(13, 17, 23);
pub const BG_SURFACE: Color32 = Color32::from_rgb(22, 27, 34);
pub const BG_ELEVATED: Color32 = Color32::from_rgb(30, 37, 46);
pub const BORDER_SUBTLE: Color32 = Color32::from_rgb(48, 54, 61);
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(230, 237, 243);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(139, 148, 158);

pub const COLOR_INBOUND: Color32 = Color32::from_rgb(56, 189, 248); // Cyan
pub const COLOR_OUTBOUND: Color32 = Color32::from_rgb(251, 146, 60); // Orange
pub const COLOR_TRANSIT: Color32 = Color32::from_rgb(52, 211, 153); // Green
pub const COLOR_LOCAL: Color32 = Color32::from_rgb(167, 139, 250); // Violet
pub const COLOR_ACCENT: Color32 = Color32::from_rgb(59, 130, 246);
pub const COLOR_WARNING: Color32 = Color32::from_rgb(245, 158, 11);
pub const COLOR_ERROR: Color32 = Color32::from_rgb(248, 113, 113);

/// Applies the dark observability theme across the `egui::Context`.
pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.dark_mode = true;
    visuals.panel_fill = BG_BASE;
    visuals.window_fill = BG_SURFACE;
    visuals.extreme_bg_color = Color32::from_rgb(9, 12, 16);
    visuals.faint_bg_color = Color32::from_rgb(26, 32, 40);
    visuals.window_stroke = Stroke::new(1.0, BORDER_SUBTLE);
    visuals.window_corner_radius = CornerRadius::same(8);

    visuals.widgets.noninteractive.bg_fill = BG_SURFACE;
    visuals.widgets.noninteractive.weak_bg_fill = BG_SURFACE;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER_SUBTLE);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(6);

    visuals.widgets.inactive.bg_fill = BG_ELEVATED;
    visuals.widgets.inactive.weak_bg_fill = BG_ELEVATED;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER_SUBTLE);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(6);

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(40, 49, 61);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(40, 49, 61);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, COLOR_ACCENT);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(6);

    visuals.widgets.active.bg_fill = Color32::from_rgb(47, 60, 76);
    visuals.widgets.active.weak_bg_fill = Color32::from_rgb(47, 60, 76);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, COLOR_INBOUND);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.corner_radius = CornerRadius::same(6);

    visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(56, 189, 248, 45);
    visuals.selection.stroke = Stroke::new(1.0, COLOR_INBOUND);

    ctx.set_visuals(visuals);

    ctx.style_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.spacing.button_padding = Vec2::new(8.0, 4.0);
        style.spacing.window_margin = egui::Margin::same(10);
    });
}

/// Returns a consistent badge/chart color for a transport/network protocol.
pub fn protocol_color(proto: Protocol) -> Color32 {
    match proto {
        Protocol::Tcp => Color32::from_rgb(56, 189, 248), // Sky blue
        Protocol::Udp => Color32::from_rgb(52, 211, 153), // Emerald
        Protocol::Icmp => Color32::from_rgb(251, 191, 36), // Amber
        Protocol::Icmpv6 => Color32::from_rgb(167, 139, 250), // Violet
        Protocol::Arp => Color32::from_rgb(244, 114, 182), // Pink
        Protocol::Other(_) => Color32::from_rgb(148, 163, 184), // Slate
    }
}

/// Returns a color representing traffic direction.
pub fn direction_color(dir: Direction) -> Color32 {
    match dir {
        Direction::Inbound => COLOR_INBOUND,
        Direction::Outbound => COLOR_OUTBOUND,
        Direction::Local => COLOR_LOCAL,
        Direction::Transit => COLOR_TRANSIT,
    }
}

/// Returns a color representing IP address scope.
pub fn scope_color(scope: IpScope) -> Color32 {
    match scope {
        IpScope::LocalHost => COLOR_INBOUND,
        IpScope::Loopback => COLOR_LOCAL,
        IpScope::Private => COLOR_TRANSIT,
        IpScope::LinkLocal => Color32::from_rgb(251, 191, 36),
        IpScope::Multicast => Color32::from_rgb(244, 114, 182),
        IpScope::Public => COLOR_OUTBOUND,
    }
}

/// Draws a 60-second area/line throughput chart for Inbound, Outbound, and Transit traffic.
pub fn draw_throughput_chart(ui: &mut egui::Ui, samples: &[ThroughputSample]) {
    let available_w = ui.available_width().max(180.0);
    let desired_size = Vec2::new(available_w, 128.0);
    let (response, painter) = ui.allocate_painter(desired_size, Sense::hover());
    let rect = response.rect;

    painter.rect_filled(rect, CornerRadius::same(6), Color32::from_rgb(11, 15, 20));
    painter.rect_stroke(
        rect,
        CornerRadius::same(6),
        Stroke::new(1.0, BORDER_SUBTLE),
        egui::StrokeKind::Inside,
    );

    let inner = rect.shrink2(Vec2::new(10.0, 12.0));
    if inner.width() <= 10.0 || inner.height() <= 10.0 {
        return;
    }

    let plot_top = inner.top() + 16.0;
    let plot_bottom = inner.bottom() - 4.0;
    let plot_rect = Rect::from_min_max(
        Pos2::new(inner.left(), plot_top),
        Pos2::new(inner.right(), plot_bottom),
    );

    if plot_rect.height() <= 4.0 || samples.is_empty() {
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "No throughput samples yet",
            FontId::proportional(12.0),
            TEXT_MUTED,
        );
        return;
    }

    let has_transit = samples.iter().any(|s| s.transit_bytes > 0);
    let max_bytes = samples
        .iter()
        .map(|s| {
            let m = s.inbound_bytes.max(s.outbound_bytes);
            if has_transit {
                m.max(s.transit_bytes)
            } else {
                m
            }
        })
        .max()
        .unwrap_or(0)
        .max(1024);
    let max_bps = max_bytes as f64;

    // Horizontal gridlines (100%, 50%, 0%)
    for frac in [0.0_f32, 0.5, 1.0] {
        let y = plot_rect.bottom() - frac * plot_rect.height();
        painter.line_segment(
            [
                Pos2::new(plot_rect.left(), y),
                Pos2::new(plot_rect.right(), y),
            ],
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(139, 148, 158, 35)),
        );
    }

    // Y-axis max label and legend at top of chart
    painter.text(
        Pos2::new(inner.left(), inner.top()),
        Align2::LEFT_TOP,
        format!("Peak: {}", format_rate(max_bps)),
        FontId::monospace(10.5),
        TEXT_MUTED,
    );

    draw_legend_item(
        &painter,
        Pos2::new(
            inner.right() - (if has_transit { 210.0 } else { 142.0 }),
            inner.top() + 5.0,
        ),
        COLOR_INBOUND,
        "Inbound",
    );
    draw_legend_item(
        &painter,
        Pos2::new(
            inner.right() - (if has_transit { 140.0 } else { 68.0 }),
            inner.top() + 5.0,
        ),
        COLOR_OUTBOUND,
        "Outbound",
    );
    if has_transit {
        draw_legend_item(
            &painter,
            Pos2::new(inner.right() - 62.0, inner.top() + 5.0),
            COLOR_TRANSIT,
            "Transit",
        );
    }

    let n = samples.len();
    let x_for = |idx: usize| -> f32 {
        if n <= 1 {
            plot_rect.center().x
        } else {
            plot_rect.left() + (idx as f32 / (n - 1) as f32) * plot_rect.width()
        }
    };
    let y_for = |bytes: u64| -> f32 {
        let ratio = (bytes as f64 / max_bps).clamp(0.0, 1.0) as f32;
        plot_rect.bottom() - ratio * plot_rect.height()
    };

    let draw_series = |extract: fn(&ThroughputSample) -> u64, color: Color32| {
        let points: Vec<Pos2> = samples
            .iter()
            .enumerate()
            .map(|(i, s)| Pos2::new(x_for(i), y_for(extract(s))))
            .collect();

        if points.len() >= 2 {
            let fill = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 34);
            let mut mesh = Mesh::default();
            for p in &points {
                mesh.colored_vertex(*p, fill);
                mesh.colored_vertex(Pos2::new(p.x, plot_rect.bottom()), Color32::TRANSPARENT);
            }
            for i in 0..(points.len() - 1) {
                let b = (i * 2) as u32;
                mesh.add_triangle(b, b + 1, b + 2);
                mesh.add_triangle(b + 1, b + 3, b + 2);
            }
            painter.add(epaint::Shape::mesh(mesh));
            painter.add(epaint::PathShape::line(points, Stroke::new(1.75, color)));
        } else if let Some(p) = points.first() {
            painter.circle_filled(*p, 2.5, color);
        }
    };

    if has_transit {
        draw_series(|s| s.transit_bytes, COLOR_TRANSIT);
    }
    draw_series(|s| s.outbound_bytes, COLOR_OUTBOUND);
    draw_series(|s| s.inbound_bytes, COLOR_INBOUND);

    // Pointer hover inspection
    if response.hovered()
        && let Some(pos) = response.hover_pos()
    {
        let idx = if n <= 1 {
            0
        } else {
            let rel = ((pos.x - plot_rect.left()) / plot_rect.width()).clamp(0.0, 1.0);
            ((rel * (n - 1) as f32).round() as usize).min(n - 1)
        };
        let sample = &samples[idx];
        let x = x_for(idx);

        painter.line_segment(
            [
                Pos2::new(x, plot_rect.top()),
                Pos2::new(x, plot_rect.bottom()),
            ],
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(230, 237, 243, 90)),
        );
        painter.circle_filled(
            Pos2::new(x, y_for(sample.inbound_bytes)),
            3.0,
            COLOR_INBOUND,
        );
        painter.circle_filled(
            Pos2::new(x, y_for(sample.outbound_bytes)),
            3.0,
            COLOR_OUTBOUND,
        );
        if has_transit {
            painter.circle_filled(
                Pos2::new(x, y_for(sample.transit_bytes)),
                3.0,
                COLOR_TRANSIT,
            );
        }

        let ts = UNIX_EPOCH + Duration::from_secs(sample.epoch_sec);
        let clock = format_clock_time(ts);
        response.on_hover_ui(|ui| {
            ui.label(
                egui::RichText::new(format!("UTC {clock}"))
                    .strong()
                    .monospace(),
            );
            ui.colored_label(
                COLOR_INBOUND,
                format!("Inbound:  {}", format_rate(sample.inbound_bytes as f64)),
            );
            ui.colored_label(
                COLOR_OUTBOUND,
                format!("Outbound: {}", format_rate(sample.outbound_bytes as f64)),
            );
            if has_transit || sample.transit_bytes > 0 {
                ui.colored_label(
                    COLOR_TRANSIT,
                    format!("Transit:  {}", format_rate(sample.transit_bytes as f64)),
                );
            }
            ui.label(format!(
                "Total: {} ({} pkts)",
                format_rate(sample.total_bytes as f64),
                sample.packets
            ));
        });
    }
}

fn draw_legend_item(painter: &egui::Painter, center: Pos2, color: Color32, label: &str) {
    painter.circle_filled(center, 3.5, color);
    painter.text(
        Pos2::new(center.x + 7.0, center.y),
        Align2::LEFT_CENTER,
        label,
        FontId::proportional(10.5),
        TEXT_MUTED,
    );
}

/// Draws a stacked protocol share bar, protocol badges, and top 6 active ports.
pub fn draw_protocol_and_ports(ui: &mut egui::Ui, store: &TrafficStore) {
    ui.vertical(|ui| {
        ui.label(
            egui::RichText::new("Protocols & Top Ports")
                .size(12.0)
                .color(TEXT_MUTED)
                .strong(),
        );

        let total_bytes = store.total_bytes();
        let mut protos: Vec<(Protocol, u64, u64)> = store
            .protocol_totals()
            .iter()
            .map(|(&p, &(pkts, bytes))| (p, pkts, bytes))
            .collect();
        protos.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));

        // Stacked horizontal bar
        let bar_w = ui.available_width().max(120.0);
        let (bar_rect, _) = ui.allocate_exact_size(Vec2::new(bar_w, 10.0), Sense::hover());
        let painter = ui.painter();
        painter.rect_filled(
            bar_rect,
            CornerRadius::same(4),
            Color32::from_rgb(16, 20, 26),
        );

        if total_bytes > 0 && !protos.is_empty() {
            let mut cursor_x = bar_rect.left();
            for (idx, (proto, _, bytes)) in protos.iter().enumerate() {
                let frac = (*bytes as f64 / total_bytes as f64) as f32;
                let seg_w = if idx + 1 == protos.len() {
                    (bar_rect.right() - cursor_x).max(0.0)
                } else {
                    (frac * bar_rect.width())
                        .max(2.0)
                        .min(bar_rect.right() - cursor_x)
                };
                if seg_w > 0.0 {
                    let seg = Rect::from_min_size(
                        Pos2::new(cursor_x, bar_rect.top()),
                        Vec2::new(seg_w, bar_rect.height()),
                    );
                    painter.rect_filled(seg, CornerRadius::ZERO, protocol_color(*proto));
                    cursor_x += seg_w;
                }
            }
        }

        // Protocol badges
        if protos.is_empty() {
            ui.label(
                egui::RichText::new("No protocol traffic yet")
                    .color(TEXT_MUTED)
                    .size(11.5),
            );
        } else {
            ui.horizontal_wrapped(|ui| {
                for (proto, _pkts, bytes) in protos.iter().take(6) {
                    let pct = if total_bytes > 0 {
                        (*bytes as f64 / total_bytes as f64) * 100.0
                    } else {
                        0.0
                    };
                    let color = protocol_color(*proto);
                    egui::Frame::NONE
                        .fill(Color32::from_rgba_unmultiplied(
                            color.r(),
                            color.g(),
                            color.b(),
                            26,
                        ))
                        .stroke(Stroke::new(
                            1.0,
                            Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 100),
                        ))
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} {pct:.0}% ({})",
                                    proto.name(),
                                    format_bytes(*bytes)
                                ))
                                .size(11.0)
                                .color(color),
                            );
                        });
                }
            });
        }

        ui.add_space(2.0);
        // Top 6 ports
        let top_ports = store.top_ports(6);
        if !top_ports.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new("Top Ports:")
                        .size(11.0)
                        .color(TEXT_MUTED),
                );
                for (port, _pkts, bytes) in top_ports {
                    let label = match well_known_port_name(port) {
                        Some(svc) => format!("{port}/{svc} ({})", format_bytes(bytes)),
                        None => format!("{port} ({})", format_bytes(bytes)),
                    };
                    egui::Frame::NONE
                        .fill(BG_ELEVATED)
                        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(egui::Margin::symmetric(5, 1))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(label)
                                    .size(10.5)
                                    .monospace()
                                    .color(TEXT_PRIMARY),
                            );
                        });
                }
            });
        }
    });
}

/// Draws a compact split horizontal bar showing Sent (orange) vs Received (cyan) ratio.
pub fn draw_sent_recv_bar(ui: &mut egui::Ui, sent: u64, recv: u64) {
    let desired = Vec2::new(72.0, 10.0);
    let (rect, response) = ui.allocate_exact_size(desired, Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(3), Color32::from_rgb(16, 20, 26));

    let total = sent.saturating_add(recv);
    if total > 0 {
        let sent_frac = (sent as f64 / total as f64) as f32;
        let sent_w = (sent_frac * rect.width()).clamp(0.0, rect.width());
        if sent_w > 0.5 {
            let sent_rect = Rect::from_min_size(rect.min, Vec2::new(sent_w, rect.height()));
            painter.rect_filled(sent_rect, CornerRadius::same(2), COLOR_OUTBOUND);
        }
        let recv_w = (rect.width() - sent_w).max(0.0);
        if recv_w > 0.5 {
            let recv_rect = Rect::from_min_size(
                Pos2::new(rect.left() + sent_w, rect.top()),
                Vec2::new(recv_w, rect.height()),
            );
            painter.rect_filled(recv_rect, CornerRadius::same(2), COLOR_INBOUND);
        }
    }

    response.on_hover_text(format!(
        "Sent: {} / Recv: {}",
        format_bytes(sent),
        format_bytes(recv)
    ));
}

/// Formats `ts` relative to `ref_time` (e.g., `"now"`, `"4s ago"`, `"2m ago"`).
pub fn format_relative_time(ts: SystemTime, ref_time: SystemTime) -> String {
    let Ok(delta) = ref_time.duration_since(ts) else {
        return "now".to_string();
    };
    let secs = delta.as_secs();
    if secs < 1 {
        "now".to_string()
    } else if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

/// Formats a `SystemTime` as UTC `HH:MM:SS.mmm` derived from `UNIX_EPOCH`.
pub fn format_clock_time(ts: SystemTime) -> String {
    let dur = ts.duration_since(UNIX_EPOCH).unwrap_or_default();
    let total_secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let day_secs = total_secs % 86_400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}.{millis:03}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_clock_and_relative_time() {
        let base = UNIX_EPOCH + Duration::from_millis(3_661_234); // 01:01:01.234 UTC
        assert_eq!(format_clock_time(base), "01:01:01.234");
        assert_eq!(
            format_clock_time(UNIX_EPOCH + Duration::from_secs(86_400 + 3600)),
            "01:00:00.000"
        );

        assert_eq!(format_relative_time(base, base), "now");
        assert_eq!(
            format_relative_time(base, base + Duration::from_secs(4)),
            "4s ago"
        );
        assert_eq!(
            format_relative_time(base, base + Duration::from_secs(125)),
            "2m ago"
        );
        assert_eq!(
            format_relative_time(base, base + Duration::from_secs(7200)),
            "2h ago"
        );
        assert_eq!(
            format_relative_time(base + Duration::from_secs(5), base),
            "now"
        );
    }
}
