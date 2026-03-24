import html
import sys
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import (
    APP_AUTHOR,
    APP_NAME,
    APP_VERSION,
    SEVERITY_COLOR,
    SEVERITY_ICON,
    export_html,
    export_json,
    export_txt,
    get_context,
    scan_target,
)
from core.models import Finding


def resolve_icon_path() -> Optional[Path]:
    # CHANGE: keep runtime icon resolution independent from the legacy Flet implementation
    candidate = Path(__file__).resolve().parent.parent / "logo" / "logo.ico"
    return candidate if candidate.is_file() else None


class ScannerMainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.findings: List[Finding] = []
        self.filtered_findings: List[Finding] = []
        self.selected_finding: Optional[Finding] = None

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(1460, 920)
        icon_path = resolve_icon_path()
        if icon_path is not None:
            self.setWindowIcon(QIcon(str(icon_path)))  # CHANGE: keep the desktop app icon consistent with packaged builds

        self.path_input = QLineEdit()
        self.findings_list = QListWidget()
        self.detail_text = QTextEdit()
        self.stats_label = QLabel("Нет данных")
        self.stats_label.setObjectName("statsLabel")
        self.status_label = QLabel("Готов к сканированию")
        self.status_label.setObjectName("statusLabel")
        self.results_hint_label = QLabel("Сканирование ещё не запускалось")
        self.filter_boxes: Dict[str, QCheckBox] = {}
        self.copy_code_button: Optional[QPushButton] = None
        self.copy_context_button: Optional[QPushButton] = None

        self._build_ui()
        self._apply_styles()
        self._set_detail_empty_state(
            "Выберите файл или папку и запустите сканирование, чтобы увидеть структурированные детали находок."
        )

    def _build_ui(self) -> None:
        # CHANGE: build a dedicated modern Qt layout instead of the fragile monolithic Flet UI
        central_widget = QWidget()
        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(18, 18, 18, 18)
        root_layout.setSpacing(14)

        root_layout.addWidget(self._build_header())
        root_layout.addWidget(self._build_toolbar())
        root_layout.addWidget(self._build_split_view(), 1)
        root_layout.addWidget(self._build_footer())

        self.setCentralWidget(central_widget)

        export_menu = self.menuBar().addMenu("Экспорт")
        txt_action = QAction("TXT", self)
        json_action = QAction("JSON", self)
        html_action = QAction("HTML", self)
        txt_action.triggered.connect(lambda: self.export_report("txt"))
        json_action.triggered.connect(lambda: self.export_report("json"))
        html_action.triggered.connect(lambda: self.export_report("html"))
        export_menu.addActions([txt_action, json_action, html_action])

    def _build_header(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("headerPanel")  # CHANGE: style the main header explicitly so borders do not leak onto inner text blocks
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(22)

        branding = QVBoxLayout()
        title = QLabel(APP_NAME)
        title.setObjectName("headerTitle")
        subtitle = QLabel(f"v{APP_VERSION} • {APP_AUTHOR} • Security analysis for Rust Oxide plugins")
        subtitle.setObjectName("headerSubtitle")
        branding.addWidget(title)
        branding.addWidget(subtitle)
        branding.addStretch(1)

        promo_card = QFrame()
        promo_card.setObjectName("promoCard")
        promo_layout = QVBoxLayout(promo_card)
        promo_layout.setContentsMargins(20, 18, 20, 18)
        promo_layout.setSpacing(10)

        promo_badge = QLabel("RELIVE RUST SERVER")
        promo_badge.setObjectName("promoBadge")
        promo_title = QLabel("Залетай на сервер")
        promo_title.setObjectName("promoTitle")
        promo_text = QLabel("Уютный Rust-сервер, активное комьюнити и Discord для быстрого старта.")
        promo_text.setWordWrap(True)
        promo_text.setObjectName("promoText")
        promo_buttons = QHBoxLayout()
        promo_buttons.setSpacing(8)
        site_button = QPushButton("Открыть сайт")
        site_button.setObjectName("promoPrimaryButton")
        site_button.clicked.connect(lambda: self.open_link("https://relive.gamestores.app", "сайт"))
        discord_button = QPushButton("Discord")
        discord_button.setObjectName("secondaryPromoButton")
        discord_button.clicked.connect(lambda: self.open_link("https://discord.gg/52JTSR6m6j", "Discord"))
        promo_buttons.addWidget(site_button)
        promo_buttons.addWidget(discord_button)

        promo_layout.addWidget(promo_badge)
        promo_layout.addWidget(promo_title)
        promo_layout.addWidget(promo_text)
        promo_layout.addLayout(promo_buttons)

        layout.addLayout(branding, 2)  # CHANGE: give the promo card more room to grow leftward within the header composition
        layout.addWidget(promo_card, 1)  # CHANGE: expand the promo card area without changing its vertical footprint
        return frame

    def _build_toolbar(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("toolbarPanel")  # CHANGE: keep toolbar chrome explicit instead of using a blanket QFrame border
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(14)

        path_row = QHBoxLayout()
        path_row.setSpacing(10)
        self.path_input.setPlaceholderText("Выберите .cs файл или папку с плагинами")
        self.path_input.setObjectName("pathInput")  # CHANGE: give the main path field a premium focused style distinct from secondary surfaces
        browse_file_button = QPushButton("Файл")
        browse_file_button.setObjectName("secondaryAction")
        browse_folder_button = QPushButton("Папка")
        browse_folder_button.setObjectName("secondaryAction")
        scan_button = QPushButton("Сканировать")
        scan_button.setObjectName("primaryAction")
        browse_file_button.clicked.connect(self.pick_file)
        browse_folder_button.clicked.connect(self.pick_folder)
        scan_button.clicked.connect(self.start_scan)

        path_row.addWidget(self.path_input, 1)
        path_row.addWidget(browse_file_button)
        path_row.addWidget(browse_folder_button)
        path_row.addWidget(scan_button)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(14)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            checkbox = QCheckBox(f"{SEVERITY_ICON[severity]} {severity}")
            checkbox.setChecked(True)
            checkbox.setObjectName("filterChip")
            checkbox.stateChanged.connect(self.refresh_findings_list)
            self.filter_boxes[severity] = checkbox
            filter_row.addWidget(checkbox)
        filter_row.addStretch(1)

        layout.addLayout(path_row)
        layout.addLayout(filter_row)
        return frame

    def _build_split_view(self) -> QWidget:
        splitter = QSplitter(Qt.Horizontal)

        left_panel = QFrame()
        left_panel.setObjectName("contentPanel")  # CHANGE: scope panel styling only to actual card surfaces
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(16, 16, 16, 16)
        left_layout.setSpacing(12)
        left_title = QLabel("Найденные проблемы")
        left_title.setObjectName("panelTitle")
        self.results_hint_label.setObjectName("panelHint")
        self.findings_list.currentRowChanged.connect(self.on_finding_selected)
        self.findings_list.setSpacing(8)  # CHANGE: add breathing room between premium list cards
        left_layout.addWidget(left_title)
        left_layout.addWidget(self.results_hint_label)
        left_layout.addWidget(self.findings_list, 1)

        right_panel = QFrame()
        right_panel.setObjectName("contentPanel")  # CHANGE: scope panel styling only to actual card surfaces
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(16, 16, 16, 16)
        right_layout.setSpacing(12)
        right_title = QLabel("Детали находки")
        right_title.setObjectName("panelTitle")
        self.detail_text.setReadOnly(True)
        self.detail_text.setPlaceholderText("Выберите находку слева, чтобы увидеть детали")
        self.detail_text.setObjectName("detailSurface")

        action_row = QHBoxLayout()
        self.copy_code_button = QPushButton("Копировать код")
        self.copy_code_button.setObjectName("secondaryAction")
        self.copy_context_button = QPushButton("Копировать контекст")
        self.copy_context_button.setObjectName("secondaryAction")
        self.copy_code_button.clicked.connect(self.copy_code)
        self.copy_context_button.clicked.connect(self.copy_context)
        action_row.addWidget(self.copy_code_button)
        action_row.addWidget(self.copy_context_button)
        action_row.addStretch(1)

        right_layout.addWidget(right_title)
        right_layout.addWidget(self.detail_text, 1)
        right_layout.addLayout(action_row)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([520, 860])
        return splitter

    def _build_footer(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("footerPanel")  # CHANGE: style footer explicitly and avoid accidental borders around child text
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(22, 16, 22, 16)
        layout.setSpacing(12)

        export_txt_button = QPushButton("TXT")
        export_txt_button.setObjectName("secondaryAction")
        export_json_button = QPushButton("JSON")
        export_json_button.setObjectName("secondaryAction")
        export_html_button = QPushButton("HTML")
        export_html_button.setObjectName("secondaryAction")
        export_txt_button.clicked.connect(lambda: self.export_report("txt"))
        export_json_button.clicked.connect(lambda: self.export_report("json"))
        export_html_button.clicked.connect(lambda: self.export_report("html"))

        export_label = QLabel("Экспорт")
        export_label.setObjectName("footerLabel")
        layout.addWidget(self.stats_label, 1)
        layout.addWidget(self.status_label, 1)
        layout.addWidget(export_label)
        layout.addWidget(export_txt_button)
        layout.addWidget(export_json_button)
        layout.addWidget(export_html_button)
        return frame

    def _apply_styles(self) -> None:
        # CHANGE: push the working PySide UI toward a cleaner premium soft-panel visual system without touching scanner behavior
        self.setStyleSheet(
            """
            QMainWindow, QWidget { background: #09111b; color: #e2e8f0; font-family: Segoe UI, Arial; }
            QFrame { background: transparent; border: none; }
            QFrame#headerPanel, QFrame#toolbarPanel, QFrame#contentPanel, QFrame#footerPanel {
                background: #101a28;
                border: 1px solid rgba(154, 184, 217, 0.07);
                border-radius: 24px;
            }
            QLabel#headerTitle { font-size: 31px; font-weight: 800; color: #f8fafc; letter-spacing: 0.45px; }
            QLabel#headerSubtitle { color: #90a6bf; font-size: 12px; padding-top: 2px; }
            QLabel#panelTitle { font-size: 17px; font-weight: 700; color: #e8f1fb; }
            QLabel#panelHint { color: #7f94ac; font-size: 12px; padding-bottom: 2px; }
            QLineEdit, QTextEdit, QListWidget {
                background: #0d1622;
                border: 1px solid #182434;
                border-radius: 16px;
                padding: 12px;
                selection-background-color: #24496f;
            }
            QLineEdit#pathInput {
                background: #0c1520;
                border: 1px solid #213247;
                border-radius: 18px;
                padding: 13px 15px;
                font-size: 13px;
            }
            QLineEdit#pathInput:focus, QTextEdit#detailSurface:focus, QListWidget:focus {
                border: 1px solid #31557f;
            }
            QListWidget { outline: none; }
            QListWidget::item { margin: 0; padding: 0; border: none; background: transparent; }
            QPushButton {
                background: #142436;
                border: 1px solid #22354d;
                border-radius: 14px;
                padding: 9px 15px;
                color: #eff6ff;
                font-weight: 600;
            }
            QPushButton:hover { background: #1b3047; border: 1px solid #2a4362; }
            QPushButton:disabled { background: #101722; color: #6f8196; border: 1px solid #162131; }
            QPushButton#secondaryAction { background: #101f2f; border: 1px solid #1e3147; }
            QPushButton#secondaryAction:hover { background: #16283d; }
            QPushButton#primaryAction {
                background: #48b6ff;
                color: #07111e;
                border: 1px solid #78cbff;
                font-weight: 800;
                padding: 10px 18px;
            }
            QPushButton#primaryAction:hover { background: #6cc5ff; }
            QCheckBox#filterChip {
                spacing: 8px;
                color: #d9e8ff;
                background: #0e1824;
                border: 1px solid #1a293a;
                border-radius: 14px;
                padding: 8px 11px;
                font-weight: 600;
            }
            QCheckBox#filterChip::indicator { width: 15px; height: 15px; }
            QLabel#promoBadge {
                color: #50e341;
                font-size: 15px;
                font-weight: 900;
                letter-spacing: 1.6px;
                padding-bottom: 2px;
            }
            QLabel#promoTitle { color: #ffffff; font-size: 21px; font-weight: 800; }
            QLabel#promoText { color: #c3d7eb; font-size: 12px; line-height: 1.42em; }
            QFrame#promoCard {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #132233, stop:0.45 #182a40, stop:1 #1e3550);
                border: 1px solid rgba(80, 227, 65, 0.12);
                border-radius: 26px;
            }
            QPushButton#promoPrimaryButton { background: #f4c95d; color: #131b25; border: 1px solid #f7d989; font-weight: 800; }
            QPushButton#promoPrimaryButton:hover { background: #f7d989; }
            QPushButton#secondaryPromoButton { background: rgba(18, 33, 50, 0.78); border: 1px solid #314861; }
            QPushButton#secondaryPromoButton:hover { background: #26384f; }
            QLabel#statsLabel { color: #dfefff; font-size: 13px; font-weight: 700; }
            QLabel#statusLabel { color: #84b8df; font-size: 12px; }
            QLabel#footerLabel { color: #89a8c3; font-size: 12px; font-weight: 700; padding-right: 4px; }
            QFrame#findingCard {
                background: #0f1825;
                border: 1px solid #172434;
                border-radius: 18px;
            }
            QFrame#findingCard[selected="true"] {
                background: #15304a;
                border: 1px solid #3a709f;
            }
            QLabel#findingTitle { color: #f8fbff; font-size: 13px; font-weight: 700; }
            QLabel#findingMeta { color: #90a8c1; font-size: 11px; }
            QLabel#findingBadge {
                color: #08111c;
                font-size: 10px;
                font-weight: 800;
                padding: 5px 9px;
                border-radius: 999px;
                min-width: 72px;
            }
            QLabel#findingRuleId { color: #d7e7fb; font-size: 11px; font-weight: 700; }
            QSplitter::handle { background: #0b1320; width: 8px; }
            QMenuBar { background: #09111b; color: #dbeafe; padding: 4px; }
            QMenuBar::item { background: transparent; padding: 6px 10px; border-radius: 8px; }
            QMenuBar::item:selected { background: #132033; }
            QMenu { background: #101a28; color: #e2e8f0; border: 1px solid #1f3047; border-radius: 12px; padding: 6px; }
            QMenu::item { padding: 8px 16px; border-radius: 8px; }
            QMenu::item:selected { background: #17314c; }
            """
        )

    def pick_file(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите плагин", str(Path.cwd()), "C# Files (*.cs)")
        if file_path:
            self.path_input.setText(file_path)
            self.status_label.setText("Файл выбран")

    def pick_folder(self) -> None:
        folder_path = QFileDialog.getExistingDirectory(self, "Выберите папку", str(Path.cwd()))
        if folder_path:
            self.path_input.setText(folder_path)
            self.status_label.setText("Папка выбрана")

    def start_scan(self) -> None:
        target_path = self.path_input.text().strip()
        if not target_path:
            self.show_error("Укажите файл или папку для сканирования.")
            return

        self.findings = scan_target(target_path)
        self.selected_finding = None
        self.refresh_findings_list()
        self.update_stats()
        self.status_label.setText(
            f"Найдено проблем: {len(self.findings)}" if self.findings else "Подозрительный код не обнаружен"
        )

    def refresh_findings_list(self) -> None:
        self.findings_list.clear()
        self.selected_finding = None
        self._update_detail_actions(False)
        self.filtered_findings = [finding for finding in self.findings if self.filter_boxes[finding.rule.severity].isChecked()]
        for finding in self.filtered_findings:
            item = QListWidgetItem()
            item.setData(Qt.UserRole, finding)
            card_widget = self._build_finding_item_widget(finding, selected=False)
            item.setSizeHint(card_widget.sizeHint())
            self.findings_list.addItem(item)
            self.findings_list.setItemWidget(item, card_widget)

        if self.findings and self.filtered_findings:
            self.results_hint_label.setText(f"Показано {len(self.filtered_findings)} из {len(self.findings)} находок")
            self.findings_list.setCurrentRow(0)
        elif self.findings:
            self.results_hint_label.setText("Текущие фильтры скрыли все находки")
            self._set_detail_empty_state("Нет находок для текущих фильтров. Включите больше severity слева.")
        else:
            self.results_hint_label.setText("Сканирование завершено: находок нет")
            self._set_detail_empty_state("Сканирование не выявило подозрительных совпадений для выбранного пути.")

    def on_finding_selected(self, index: int) -> None:
        if index < 0 or index >= len(self.filtered_findings):
            self.selected_finding = None
            self._update_detail_actions(False)
            self._sync_finding_card_selection(-1)
            return
        self.selected_finding = self.filtered_findings[index]
        self._update_detail_actions(True)
        self._sync_finding_card_selection(index)
        self.detail_text.setHtml(self.render_detail(self.selected_finding))

    def _build_finding_item_widget(self, finding: Finding, selected: bool) -> QWidget:
        # CHANGE: render premium custom list cards instead of plain text rows for a richer production-style findings list
        card = QFrame()
        card.setObjectName("findingCard")
        card.setProperty("selected", selected)

        layout = QHBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)

        badge = QLabel(finding.rule.severity)
        badge.setObjectName("findingBadge")
        badge.setAlignment(Qt.AlignCenter)
        badge.setStyleSheet(f"background:{SEVERITY_COLOR[finding.rule.severity]};")

        body_layout = QVBoxLayout()
        body_layout.setSpacing(4)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)
        rule_id = QLabel(finding.rule.id)
        rule_id.setObjectName("findingRuleId")
        title = QLabel(finding.rule.title)
        title.setObjectName("findingTitle")
        title.setWordWrap(True)
        top_row.addWidget(rule_id, 0)
        top_row.addWidget(title, 1)

        meta_primary = QLabel(f"{Path(finding.filepath).name} • Строка {finding.line_no}")
        meta_primary.setObjectName("findingMeta")
        meta_secondary = QLabel(f"{finding.rule.category} • {SEVERITY_ICON[finding.rule.severity]} {finding.rule.severity}")
        meta_secondary.setObjectName("findingMeta")

        body_layout.addLayout(top_row)
        body_layout.addWidget(meta_primary)
        body_layout.addWidget(meta_secondary)

        layout.addWidget(badge, 0, Qt.AlignTop)
        layout.addLayout(body_layout, 1)
        return card

    def _sync_finding_card_selection(self, selected_index: int) -> None:
        # CHANGE: keep custom list cards visually in sync with QListWidget selection state
        for index in range(self.findings_list.count()):
            item = self.findings_list.item(index)
            widget = self.findings_list.itemWidget(item)
            if widget is None:
                continue
            widget.setProperty("selected", index == selected_index)
            widget.style().unpolish(widget)
            widget.style().polish(widget)
            widget.update()

    def render_detail(self, finding: Finding) -> str:
        # CHANGE: reduce the heavy boxy look by using softer section dividers and cleaner typography in the detail panel
        context = get_context(finding.filepath, finding.line_no)
        file_name = Path(finding.filepath).name
        severity_color = SEVERITY_COLOR[finding.rule.severity]

        return f"""
        <html>
            <body style=\"font-family:'Segoe UI'; color:#e2e8f0; background:#0f1726;\">
                <div style=\"margin-bottom:14px; padding-bottom:12px; border-bottom:1px solid #1c2a3d;\">
                    <div style=\"display:inline-block; padding:4px 10px; border-radius:999px; font-size:11px; font-weight:700; letter-spacing:0.6px; color:#08111c; background:{severity_color};\">{html.escape(finding.rule.severity)}</div>
                    <div style=\"margin-top:10px; font-size:12px; color:#8aa1bc; font-weight:600;\">{html.escape(finding.rule.id)}</div>
                    <div style=\"margin-top:4px; font-size:22px; font-weight:700; color:#f8fafc;\">{html.escape(finding.rule.title)}</div>
                </div>

                {self._render_meta_section(file_name, finding)}

                <div style=\"margin-top:18px;\">
                    <div style=\"font-size:11px; font-weight:700; letter-spacing:0.9px; text-transform:uppercase; color:#7fb9e6; margin-bottom:8px;\">Объяснение</div>
                    <div style=\"font-size:13px; line-height:1.55; color:#dbe7f5;\">{self._format_text_block(finding.rule.description)}</div>
                </div>

                <div style=\"margin-top:16px;\">{self._render_code_block('Matched text', finding.match_text)}</div>
                <div style=\"margin-top:12px;\">{self._render_code_block('Source line', finding.line_text)}</div>
                <div style=\"margin-top:12px;\">{self._render_code_block('Context', context or 'Контекст недоступен')}</div>
            </body>
        </html>
        """

    def _render_meta_section(self, file_name: str, finding: Finding) -> str:
        # CHANGE: replace the bulky metadata table box with compact softer chips for a cleaner detail panel
        meta_rows = [
            ("Category", finding.rule.category),
            ("File", file_name),
            ("Line", str(finding.line_no)),
        ]
        chips_html = "".join(
            f"""
            <div style=\"display:inline-block; margin:0 10px 10px 0; padding:8px 12px; border-radius:12px; background:#101a29; border:1px solid #1d2b40;\">
                <div style=\"font-size:10px; font-weight:700; letter-spacing:0.7px; text-transform:uppercase; color:#7fa7ca; margin-bottom:3px;\">{html.escape(label)}</div>
                <div style=\"font-size:13px; color:#f8fafc;\">{html.escape(value)}</div>
            </div>
            """
            for label, value in meta_rows
        )
        return f"""
        <div style=\"margin-top:4px;\">
            <div style=\"font-size:11px; font-weight:700; letter-spacing:0.9px; text-transform:uppercase; color:#7fb9e6; margin-bottom:10px;\">Metadata</div>
            <div>{chips_html}</div>
        </div>
        """

    def _render_code_block(self, label: str, value: str) -> str:
        # CHANGE: keep code fragments distinct but softer by removing oversized outer boxes and using cleaner section headers
        return f"""
        <div>
            <div style=\"font-size:11px; font-weight:700; letter-spacing:0.9px; text-transform:uppercase; color:#7fb9e6; margin-bottom:8px;\">{html.escape(label)}</div>
            <pre style=\"margin:0; white-space:pre-wrap; font-family:'Consolas','Courier New',monospace; font-size:12px; line-height:1.58; color:#e2e8f0; background:#101a29; border:none; border-left:3px solid #315b85; border-radius:12px; padding:13px 14px;\">{html.escape(value)}</pre>
        </div>
        """

    def _format_text_block(self, value: str) -> str:
        # CHANGE: preserve line breaks in descriptions without sacrificing safe HTML escaping
        return html.escape(value).replace("\n", "<br>")

    def _set_detail_empty_state(self, message: str) -> None:
        # CHANGE: keep the empty state informative but visually lighter than the previous boxed treatment
        self.detail_text.setHtml(
            f"""
            <html>
                <body style=\"font-family:'Segoe UI'; color:#dbe7f5; background:#0f1726;\">
                    <div style=\"margin:18px; padding:18px 0; border-bottom:1px solid #22314a;\">
                        <div style=\"font-size:16px; font-weight:700; color:#f8fafc; margin-bottom:6px;\">Панель деталей</div>
                        <div style=\"font-size:13px; line-height:1.6; color:#9fb3c8;\">{html.escape(message)}</div>
                    </div>
                </body>
            </html>
            """
        )

    def _update_detail_actions(self, enabled: bool) -> None:
        # CHANGE: keep copy actions aligned with selection state for a clearer, safer workflow
        if self.copy_code_button is not None:
            self.copy_code_button.setEnabled(enabled)
        if self.copy_context_button is not None:
            self.copy_context_button.setEnabled(enabled)

    def copy_code(self) -> None:
        if self.selected_finding is None:
            return
        QApplication.clipboard().setText(self.selected_finding.line_text)
        self.status_label.setText("Код скопирован")

    def copy_context(self) -> None:
        if self.selected_finding is None:
            return
        QApplication.clipboard().setText(get_context(self.selected_finding.filepath, self.selected_finding.line_no))
        self.status_label.setText("Контекст скопирован")

    def export_report(self, format_type: str) -> None:
        if not self.findings:
            self.show_error("Нет данных для экспорта.")
            return
        suffix = f"*.{format_type}"
        output_path, _ = QFileDialog.getSaveFileName(
            self,
            f"Сохранить отчёт ({format_type.upper()})",
            str(Path.cwd() / f"scan_report.{format_type}"),
            f"{format_type.upper()} Files ({suffix})",
        )
        if not output_path:
            return
        if format_type == "txt":
            export_txt(self.findings, output_path)
        elif format_type == "json":
            export_json(self.findings, output_path)
        else:
            export_html(self.findings, output_path)
        self.status_label.setText(f"Отчёт сохранён: {Path(output_path).name}")

    def update_stats(self) -> None:
        counts = {severity: 0 for severity in SEVERITY_COLOR}
        for finding in self.findings:
            counts[finding.rule.severity] += 1
        self.stats_label.setText(
            f"Всего: {len(self.findings)} | 🔴 {counts['CRITICAL']} | 🟠 {counts['HIGH']} | 🟡 {counts['MEDIUM']} | 🔵 {counts['LOW']} | ⚪ {counts['INFO']}"
        )

    def open_link(self, url: str, label: str) -> None:
        # CHANGE: use Python's standard browser integration for robust desktop link opening without Flet service dependencies
        try:
            webbrowser.open(url, new=2)
            self.status_label.setText(f"Открыт {label}")
        except Exception as error:
            self.show_error(f"Не удалось открыть {label}: {error}")

    def show_error(self, message: str) -> None:
        QMessageBox.warning(self, APP_NAME, message)
        self.status_label.setText(message)


def main() -> int:
    application = QApplication(sys.argv)
    application.setApplicationName(APP_NAME)
    application.setFont(QFont("Segoe UI", 10))
    window = ScannerMainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
