"""
Desktop UI Module for EVM Solidity Auditing Agent

PySide6-based desktop interface for project/session management,
model selection, and terminal integration.
"""
import sys
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from PySide6.QtCore import (
    Qt, QTimer, Signal, Slot, QThread, QUrl,
    QDir, QMimeData, QSize, QSettings
)
from PySide6.QtGui import (
    QAction, QIcon, QKeySequence, QColor, QFont,
    QTextCursor, QDesktopServices, QPalette
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QTreeWidget, QTreeWidgetItem, QListWidget,
    QListWidgetItem, QTextEdit, QLineEdit, QPushButton, QLabel,
    QComboBox, QSpinBox, QCheckBox, QGroupBox, QFormLayout,
    QFileDialog, QMessageBox, QProgressDialog, QStatusBar,
    QToolBar, QMenu, QDockWidget, QFrame, QScrollArea,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QDialog, QDialogButtonBox, QPlainTextEdit, QSizePolicy,
    QStyleFactory
)

# Import modules
from models import VulnerabilityLead, ContractInfo
from config import Severity, LeadStatus, SEVERITY_COLORS, STATUS_COLORS


class TerminalWidget(QPlainTextEdit):
    """Terminal-like widget for output"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 11))
        self.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1a1a2e;
                color: #eaeaea;
                border: 1px solid #16213e;
                border-radius: 4px;
                padding: 8px;
            }
        """)
    
    def log_info(self, message: str):
        self.appendPlainText(f"[INFO] {message}")
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
    
    def log_warning(self, message: str):
        self.appendPlainText(f"[WARN] {message}")
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
    
    def log_error(self, message: str):
        self.appendPlainText(f"[ERROR] {message}")
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
    
    def log_success(self, message: str):
        self.appendPlainText(f"[SUCCESS] {message}")
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())


class ContractTreeWidget(QTreeWidget):
    """Tree widget for displaying contract structure"""
    
    contract_selected = Signal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Name", "Type", "Details"])
        self.setAlternatingRowColors(True)
        self.setStyleSheet("""
            QTreeWidget {
                font-size: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            QTreeWidget::item {
                padding: 4px;
            }
            QTreeWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        self.itemClicked.connect(self._on_item_clicked)
    
    def load_contracts(self, contracts: List[ContractInfo]):
        self.clear()
        
        for contract in contracts:
            contract_item = QTreeWidgetItem([
                contract.name,
                contract.kind,
                f"{len(contract.functions)} functions"
            ])
            contract_item.setData(0, Qt.UserRole, contract.name)
            contract_item.setFont(0, QFont("Segoe UI", 11, QFont.Bold))
            
            # Add functions
            for func in contract.functions:
                func_item = QTreeWidgetItem([
                    func.name,
                    func.visibility,
                    func.mutability
                ])
                func_item.setData(0, Qt.UserRole, f"{contract.name}.{func.name}")
                contract_item.addChild(func_item)
            
            self.addTopLevelItem(contract_item)
        
        self.expandAll()
        self.resizeColumnToContents(0)
    
    def _on_item_clicked(self, item: QTreeWidgetItem, column: int):
        data = item.data(0, Qt.UserRole)
        if data:
            self.contract_selected.emit(str(data))


class LeadsTableWidget(QTableWidget):
    """Table widget for displaying vulnerability leads"""
    
    lead_selected = Signal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(5)
        self.setHorizontalHeaderLabels([
            "Title", "Severity", "Status", "Confidence", "Category"
        ])
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setStyleSheet("""
            QTableWidget {
                font-size: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        self.cellClicked.connect(self._on_cell_clicked)
    
    def load_leads(self, leads: List[VulnerabilityLead]):
        self.setRowCount(len(leads))
        
        for row, lead in enumerate(leads):
            # Title
            title_item = QTableWidgetItem(lead.title[:60])
            title_item.setData(Qt.UserRole, lead.id)
            self.setItem(row, 0, title_item)
            
            # Severity
            severity_item = QTableWidgetItem(lead.severity.value)
            severity_item.setBackground(QColor(SEVERITY_COLORS.get(lead.severity, "#808080")))
            severity_item.setForeground(QColor("white"))
            self.setItem(row, 1, severity_item)
            
            # Status
            status_item = QTableWidgetItem(lead.status.value)
            self.setItem(row, 2, status_item)
            
            # Confidence
            conf_item = QTableWidgetItem(f"{lead.confidence:.0%}")
            self.setItem(row, 3, conf_item)
            
            # Category
            self.setItem(row, 4, QTableWidgetItem(lead.category))
    
    def _on_cell_clicked(self, row: int, column: int):
        item = self.item(row, 0)
        if item:
            self.lead_selected.emit(item.data(Qt.UserRole))


class NewSessionDialog(QDialog):
    """Dialog for creating a new audit session"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Audit Session")
        self.setMinimumWidth(500)
        self.setStyleSheet("QLabel { font-size: 12px; }")
        
        layout = QVBoxLayout(self)
        
        # Form
        form_group = QGroupBox("Session Details")
        form_layout = QFormLayout()
        
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Enter session name")
        form_layout.addRow("Name:", self.name_edit)
        
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Select project directory")
        self.path_button = QPushButton("Browse...")
        self.path_button.clicked.connect(self._browse_path)
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(self.path_button)
        form_layout.addRow("Project Path:", path_layout)
        
        form_group.setLayout(form_layout)
        layout.addWidget(form_group)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def _browse_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select Project Directory")
        if path:
            self.path_edit.setText(path)
    
    def get_session_data(self) -> Dict[str, str]:
        return {
            "name": self.name_edit.text(),
            "path": self.path_edit.text(),
        }


class LeadDetailWidget(QWidget):
    """Widget for displaying lead details"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_lead: Optional[VulnerabilityLead] = None
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        self.title_label = QLabel("Select a lead to view details")
        self.title_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        self.title_label.setWordWrap(True)
        layout.addWidget(self.title_label)
        
        # Meta info
        meta_layout = QHBoxLayout()
        self.severity_label = QLabel()
        self.status_label = QLabel()
        self.confidence_label = QLabel()
        meta_layout.addWidget(QLabel("Severity:"))
        meta_layout.addWidget(self.severity_label)
        meta_layout.addSpacing(20)
        meta_layout.addWidget(QLabel("Status:"))
        meta_layout.addWidget(self.status_label)
        meta_layout.addSpacing(20)
        meta_layout.addWidget(QLabel("Confidence:"))
        meta_layout.addWidget(self.confidence_label)
        meta_layout.addStretch()
        layout.addLayout(meta_layout)
        
        # Description
        layout.addWidget(QLabel("<b>Description:</b>"))
        self.description_text = QTextEdit()
        self.description_text.setReadOnly(True)
        self.description_text.setMaximumHeight(100)
        layout.addWidget(self.description_text)
        
        # Attack Vector
        layout.addWidget(QLabel("<b>Attack Vector:</b>"))
        self.attack_text = QTextEdit()
        self.attack_text.setReadOnly(True)
        self.attack_text.setMaximumHeight(80)
        layout.addWidget(self.attack_text)
        
        # POC Code
        layout.addWidget(QLabel("<b>POC Code:</b>"))
        self.poc_text = QPlainTextEdit()
        self.poc_text.setReadOnly(True)
        self.poc_text.setFont(QFont("Consolas", 10))
        self.poc_text.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1a1a2e;
                color: #eaeaea;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        layout.addWidget(self.poc_text)
    
    def set_lead(self, lead: VulnerabilityLead):
        self.current_lead = lead
        self.title_label.setText(lead.title)
        
        severity_color = SEVERITY_COLORS.get(lead.severity, "#808080")
        self.severity_label.setText(
            f'<span style="color: {severity_color}; font-weight: bold;">{lead.severity.value}</span>'
        )
        
        self.status_label.setText(lead.status.value)
        self.confidence_label.setText(f"{lead.confidence:.0%}")
        
        self.description_text.setPlainText(lead.description)
        self.attack_text.setPlainText(lead.attack_vector)
        self.poc_text.setPlainText(lead.foundry_poc or "No POC generated yet")
    
    def clear(self):
        self.current_lead = None
        self.title_label.setText("Select a lead to view details")
        self.severity_label.clear()
        self.status_label.clear()
        self.confidence_label.clear()
        self.description_text.clear()
        self.attack_text.clear()
        self.poc_text.clear()


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EVM Solidity Auditing Agent")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        
        # State
        self.current_session = None
        
        self._setup_ui()
        self._setup_menu()
        self._setup_toolbar()
        self._setup_statusbar()
        self._connect_signals()
    
    def _setup_ui(self):
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Create splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # === Left Panel ===
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(10)
        
        # Session group
        session_group = QGroupBox("Session")
        session_layout = QVBoxLayout()
        
        session_buttons = QHBoxLayout()
        self.new_session_btn = QPushButton("New Session")
        self.new_session_btn.setMinimumHeight(35)
        self.open_project_btn = QPushButton("Open Project")
        self.open_project_btn.setMinimumHeight(35)
        session_buttons.addWidget(self.new_session_btn)
        session_buttons.addWidget(self.open_project_btn)
        session_layout.addLayout(session_buttons)
        
        session_group.setLayout(session_layout)
        left_layout.addWidget(session_group)
        
        # Contracts group
        contracts_group = QGroupBox("Contracts")
        contracts_layout = QVBoxLayout()
        self.contracts_tree = ContractTreeWidget()
        contracts_layout.addWidget(self.contracts_tree)
        contracts_group.setLayout(contracts_layout)
        left_layout.addWidget(contracts_group, 1)
        
        # Progress group
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(25)
        self.progress_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_label)
        progress_group.setLayout(progress_layout)
        left_layout.addWidget(progress_group)
        
        left_panel.setMaximumWidth(350)
        splitter.addWidget(left_panel)
        
        # === Middle Panel ===
        middle_panel = QTabWidget()
        
        # Leads tab
        leads_widget = QWidget()
        leads_layout = QVBoxLayout(leads_widget)
        leads_layout.setContentsMargins(5, 5, 5, 5)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        filter_layout.addWidget(self.severity_filter)
        filter_layout.addStretch()
        leads_layout.addLayout(filter_layout)
        
        # Leads table
        self.leads_table = LeadsTableWidget()
        leads_layout.addWidget(self.leads_table)
        
        middle_panel.addTab(leads_widget, "Vulnerability Leads")
        
        # Lead detail tab
        self.lead_detail = LeadDetailWidget()
        middle_panel.addTab(self.lead_detail, "Lead Details")
        
        # Source code tab
        self.source_view = QPlainTextEdit()
        self.source_view.setReadOnly(True)
        self.source_view.setFont(QFont("Consolas", 11))
        self.source_view.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1a1a2e;
                color: #eaeaea;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        middle_panel.addTab(self.source_view, "Source Code")
        
        splitter.addWidget(middle_panel)
        
        # === Right Panel ===
        right_panel = QTabWidget()
        right_panel.setMaximumWidth(400)
        
        # Terminal
        self.terminal = TerminalWidget()
        right_panel.addTab(self.terminal, "Terminal")
        
        # Chat
        chat_widget = QWidget()
        chat_layout = QVBoxLayout(chat_widget)
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Ask about the codebase...")
        self.chat_input.setMinimumHeight(35)
        chat_layout.addWidget(self.chat_history)
        chat_layout.addWidget(self.chat_input)
        right_panel.addTab(chat_widget, "AI Chat")
        
        splitter.addWidget(right_panel)
        
        # Set splitter sizes
        splitter.setSizes([250, 700, 350])
        
        main_layout.addWidget(splitter)
    
    def _setup_menu(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        new_action = QAction("&New Session", self)
        new_action.setShortcut(QKeySequence.New)
        new_action.triggered.connect(self._new_session)
        file_menu.addAction(new_action)
        
        open_action = QAction("&Open Project...", self)
        open_action.setShortcut(QKeySequence.Open)
        open_action.triggered.connect(self._open_project)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Analysis menu
        analysis_menu = menubar.addMenu("&Analysis")
        
        run_action = QAction("Run &Analysis", self)
        run_action.setShortcut(QKeySequence("Ctrl+Shift+A"))
        run_action.triggered.connect(self._run_analysis)
        analysis_menu.addAction(run_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        clear_terminal = QAction("Clear &Terminal", self)
        clear_terminal.triggered.connect(lambda: self.terminal.clear())
        view_menu.addAction(clear_terminal)
    
    def _setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Start button
        self.start_btn = QPushButton("▶ Start Audit")
        self.start_btn.setMinimumHeight(35)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2ecc71;
            }
        """)
        self.start_btn.clicked.connect(self._run_analysis)
        toolbar.addWidget(self.start_btn)
        
        toolbar.addSeparator()
        
        # Report button
        report_btn = QPushButton("📄 Generate Report")
        report_btn.setMinimumHeight(35)
        report_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #5dade2;
            }
        """)
        report_btn.clicked.connect(self._export_report)
        toolbar.addWidget(report_btn)
    
    def _setup_statusbar(self):
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready - Open a project to begin")
    
    def _connect_signals(self):
        self.new_session_btn.clicked.connect(self._new_session)
        self.open_project_btn.clicked.connect(self._open_project)
        self.contracts_tree.contract_selected.connect(self._on_contract_selected)
        self.leads_table.lead_selected.connect(self._on_lead_selected)
    
    # === Actions ===
    
    def _new_session(self):
        dialog = NewSessionDialog(self)
        if dialog.exec() == QDialog.Accepted:
            data = dialog.get_session_data()
            if data['path']:
                self._load_project(data['path'])
    
    def _open_project(self):
        path = QFileDialog.getExistingDirectory(self, "Open Project Directory")
        if path:
            self._load_project(path)
    
    def _load_project(self, path: str):
        self.terminal.log_info(f"Loading project: {path}")
        
        try:
            from modules.parser.code_parser import solidity_parser
            from modules.session.manager import session_manager
            
            # Create session
            self.current_session = session_manager.create_session(
                name=Path(path).name,
                project_path=path
            )
            
            # Parse contracts
            results = solidity_parser.parse_directory(Path(path))
            
            for result in results:
                for contract in result.contracts:
                    self.current_session.contracts.append(contract)
                    self.terminal.log_info(f"Found contract: {contract.name}")
            
            session_manager.save_current_session()
            
            # Update UI
            self.contracts_tree.load_contracts(self.current_session.contracts)
            self.statusbar.showMessage(
                f"Loaded: {len(self.current_session.contracts)} contracts"
            )
            
            self.terminal.log_success(
                f"Loaded {len(self.current_session.contracts)} contracts"
            )
            
        except Exception as e:
            self.terminal.log_error(f"Error loading project: {e}")
    
    def _run_analysis(self):
        if not self.current_session:
            QMessageBox.warning(self, "No Session", "Please open a project first.")
            return
        
        self.terminal.log_info("Starting analysis...")
        self.statusbar.showMessage("Running analysis...")
        self.progress_bar.setValue(10)
        
        # Run Slither
        try:
            from modules.slither.analyzer import slither_analyzer
            from modules.session.manager import session_manager
            
            self.terminal.log_info("Running Slither analysis...")
            self.progress_bar.setValue(30)
            
            for contract in self.current_session.contracts:
                try:
                    leads = slither_analyzer.analyze(Path(contract.file_path))
                    for lead in leads:
                        self.current_session.leads.append(lead)
                        self.terminal.log_info(f"Found: {lead.title}")
                except Exception as e:
                    self.terminal.log_warning(f"Slither error on {contract.name}: {e}")
            
            session_manager.save_current_session()
            self.leads_table.load_leads(self.current_session.leads)
            
            self.progress_bar.setValue(100)
            self.terminal.log_success(
                f"Analysis complete: {len(self.current_session.leads)} leads found"
            )
            self.statusbar.showMessage(f"Analysis complete: {len(self.current_session.leads)} leads")
            
        except Exception as e:
            self.terminal.log_error(f"Analysis error: {e}")
            self.progress_bar.setValue(0)
    
    def _on_contract_selected(self, identifier: str):
        if not self.current_session:
            return
        
        # Find contract and show source
        for contract in self.current_session.contracts:
            if contract.name == identifier or identifier.startswith(contract.name + "."):
                try:
                    source = Path(contract.file_path).read_text()
                    self.source_view.setPlainText(source)
                except Exception as e:
                    self.terminal.log_error(f"Error reading file: {e}")
                break
    
    def _on_lead_selected(self, lead_id: str):
        if not self.current_session:
            return
        
        for lead in self.current_session.leads:
            if lead.id == lead_id:
                self.lead_detail.set_lead(lead)
                break
    
    def _export_report(self):
        if not self.current_session or not self.current_session.leads:
            QMessageBox.information(
                self, "No Data",
                "No vulnerability leads to report."
            )
            return
        
        try:
            from modules.reporting.generator import report_generator
            
            # Generate report
            reports = []
            for lead in self.current_session.leads:
                report = report_generator.generate_report(lead, lead.foundry_poc or "")
                reports.append(report)
            
            path = report_generator.generate_session_report(
                self.current_session.to_dict(),
                reports,
                format="markdown"
            )
            
            if path:
                self.terminal.log_success(f"Report saved: {path}")
                QMessageBox.information(
                    self, "Report Generated",
                    f"Report saved to:\n{path}"
                )
        except Exception as e:
            self.terminal.log_error(f"Report generation error: {e}")


def main():
    """Application entry point"""
    app = QApplication(sys.argv)
    
    # Set style
    app.setStyle("Fusion")
    
    # Set up palette for better appearance
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(50, 50, 50))
    palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 220))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
    palette.setColor(QPalette.ColorRole.Text, QColor(50, 50, 50))
    palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(50, 50, 50))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(52, 152, 219))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)
    
    # Set global font
    font = QFont("Segoe UI", 11)
    app.setFont(font)
    
    # Create and show window
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
