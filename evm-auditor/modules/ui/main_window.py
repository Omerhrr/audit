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
    QDir, QMimeData, QSize
)
from PySide6.QtGui import (
    QAction, QIcon, QKeySequence, QColor, QFont,
    QTextCursor, QDesktopServices, QDragEnterEvent, QDropEvent
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QTreeWidget, QTreeWidgetItem, QListWidget,
    QListWidgetItem, QTextEdit, QLineEdit, QPushButton, QLabel,
    QComboBox, QSpinBox, QCheckBox, QGroupBox, QFormLayout,
    QFileDialog, QMessageBox, QProgressDialog, QStatusBar,
    QToolBar, QMenu, QDockWidget, QFrame, QScrollArea,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QDialog, QDialogButtonBox, QPlainTextEdit, QSizePolicy
)

# Import modules
try:
    from modules.session.manager import session_manager, SessionManager
    from modules.parser.code_parser import solidity_parser
    from modules.model.llm_service import LLMClient, ModelBrain
    from modules.slither.analyzer import slither_analyzer
    from modules.z3_solver.symbolic import z3_executor
    from modules.foundry.test_runner import FoundryIntegration
    from modules.reporting.generator import report_generator
    from modules.audit.continuous import ContinuousAuditor, AuditPhase
    from models import Session, VulnerabilityLead, ContractInfo
    from config import (
        Severity, LeadStatus, ModelProvider, SEVERITY_COLORS, STATUS_COLORS
    )
except ImportError:
    # For standalone testing
    pass


class AsyncWorker(QThread):
    """Worker thread for async operations"""
    finished = Signal(object)
    error = Signal(str)
    progress = Signal(str)
    
    def __init__(self, coro, parent=None):
        super().__init__(parent)
        self.coro = coro
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.coro)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class TerminalWidget(QPlainTextEdit):
    """Terminal-like widget for output and command execution"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3c3c3c;
            }
        """)
        self._buffer = []
    
    def append_output(self, text: str, color: str = None):
        """Append colored output"""
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        if color:
            cursor.insertHtml(f'<span style="color: {color}">{text}</span><br>')
        else:
            cursor.insertText(text + '\n')
        
        self.setTextCursor(cursor)
        self.ensureCursorVisible()
    
    def log_info(self, message: str):
        self.append_output(f"[INFO] {message}", "#4ec9b0")
    
    def log_warning(self, message: str):
        self.append_output(f"[WARN] {message}", "#dcdcaa")
    
    def log_error(self, message: str):
        self.append_output(f"[ERROR] {message}", "#f14c4c")
    
    def log_success(self, message: str):
        self.append_output(f"[SUCCESS] {message}", "#6a9955")
    
    def clear_log(self):
        self.clear()


class ContractTreeWidget(QTreeWidget):
    """Tree widget for displaying contract structure"""
    
    contract_selected = Signal(str)  # contract name
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Contracts", "Type", "Functions"])
        self.setAlternatingRowColors(True)
        self.itemClicked.connect(self._on_item_clicked)
    
    def load_contracts(self, contracts: List[ContractInfo]):
        """Load contracts into tree"""
        self.clear()
        
        for contract in contracts:
            # Create contract item
            contract_item = QTreeWidgetItem([
                contract.name,
                contract.kind,
                str(len(contract.functions))
            ])
            contract_item.setData(0, Qt.UserRole, contract.name)
            
            # Add functions
            for func in contract.functions:
                func_item = QTreeWidgetItem([
                    func.name,
                    func.visibility,
                    func.mutability
                ])
                func_item.setData(0, Qt.UserRole, f"{contract.name}.{func.name}")
                contract_item.addChild(func_item)
            
            # Add state variables
            if contract.variables:
                vars_item = QTreeWidgetItem([
                    f"Variables ({len(contract.variables)})",
                    "",
                    ""
                ])
                for var in contract.variables:
                    var_item = QTreeWidgetItem([
                        var.get('name', ''),
                        var.get('visibility', ''),
                        var.get('type', '')
                    ])
                    vars_item.addChild(var_item)
                contract_item.addChild(vars_item)
            
            # Add events
            if contract.events:
                events_item = QTreeWidgetItem([
                    f"Events ({len(contract.events)})",
                    "",
                    ""
                ])
                for event in contract.events:
                    event_item = QTreeWidgetItem([
                        event.get('name', ''),
                        "",
                        ""
                    ])
                    events_item.addChild(event_item)
                contract_item.addChild(events_item)
            
            self.addTopLevelItem(contract_item)
        
        self.expandAll()
        self.resizeColumnToContents(0)
    
    def _on_item_clicked(self, item: QTreeWidgetItem, column: int):
        data = item.data(0, Qt.UserRole)
        if data:
            self.contract_selected.emit(str(data))


class LeadsTableWidget(QTableWidget):
    """Table widget for displaying vulnerability leads"""
    
    lead_selected = Signal(str)  # lead ID
    lead_double_clicked = Signal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels([
            "ID", "Title", "Severity", "Status", "Confidence", "Category", "Contract"
        ])
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.cellClicked.connect(self._on_cell_clicked)
        self.cellDoubleClicked.connect(self._on_cell_double_clicked)
    
    def load_leads(self, leads: List[VulnerabilityLead]):
        """Load leads into table"""
        self.setRowCount(len(leads))
        
        for row, lead in enumerate(leads):
            # ID
            id_item = QTableWidgetItem(lead.id)
            id_item.setData(Qt.UserRole, lead.id)
            self.setItem(row, 0, id_item)
            
            # Title
            self.setItem(row, 1, QTableWidgetItem(lead.title[:50]))
            
            # Severity
            severity_item = QTableWidgetItem(lead.severity.value)
            severity_color = QColor(SEVERITY_COLORS.get(lead.severity, "#808080"))
            severity_item.setBackground(severity_color)
            severity_item.setForeground(QColor("white"))
            self.setItem(row, 2, severity_item)
            
            # Status
            status_item = QTableWidgetItem(lead.status.value)
            status_color = QColor(STATUS_COLORS.get(lead.status, "#808080"))
            status_item.setForeground(status_color)
            self.setItem(row, 3, status_item)
            
            # Confidence
            confidence_item = QTableWidgetItem(f"{lead.confidence:.0%}")
            self.setItem(row, 4, confidence_item)
            
            # Category
            self.setItem(row, 5, QTableWidgetItem(lead.category))
            
            # Contract
            self.setItem(row, 6, QTableWidgetItem(
                ", ".join(lead.affected_contracts[:2])
            ))
    
    def _on_cell_clicked(self, row: int, column: int):
        item = self.item(row, 0)
        if item:
            self.lead_selected.emit(item.data(Qt.UserRole))
    
    def _on_cell_double_clicked(self, row: int, column: int):
        item = self.item(row, 0)
        if item:
            self.lead_double_clicked.emit(item.data(Qt.UserRole))


class NewSessionDialog(QDialog):
    """Dialog for creating a new audit session"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Audit Session")
        self.setMinimumWidth(500)
        
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
        
        self.github_edit = QLineEdit()
        self.github_edit.setPlaceholderText("https://github.com/user/repo (optional)")
        form_layout.addRow("GitHub URL:", self.github_edit)
        
        form_group.setLayout(form_layout)
        layout.addWidget(form_group)
        
        # API Keys
        api_group = QGroupBox("API Keys (Optional)")
        api_layout = QFormLayout()
        
        self.etherscan_edit = QLineEdit()
        self.etherscan_edit.setPlaceholderText("Etherscan API key")
        self.etherscan_edit.setEchoMode(QLineEdit.Password)
        api_layout.addRow("Etherscan:", self.etherscan_edit)
        
        self.alchemy_edit = QLineEdit()
        self.alchemy_edit.setPlaceholderText("Alchemy API key")
        self.alchemy_edit.setEchoMode(QLineEdit.Password)
        api_layout.addRow("Alchemy:", self.alchemy_edit)
        
        api_group.setLayout(api_layout)
        layout.addWidget(api_group)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def _browse_path(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Project Directory"
        )
        if path:
            self.path_edit.setText(path)
    
    def get_session_data(self) -> Dict[str, str]:
        return {
            "name": self.name_edit.text(),
            "path": self.path_edit.text(),
            "github_url": self.github_edit.text(),
            "etherscan_key": self.etherscan_edit.text(),
            "alchemy_key": self.alchemy_edit.text(),
        }


class LeadDetailWidget(QWidget):
    """Widget for displaying lead details"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_lead: Optional[VulnerabilityLead] = None
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        header_layout = QHBoxLayout()
        self.title_label = QLabel("Select a lead to view details")
        self.title_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()
        
        self.generate_poc_btn = QPushButton("Generate POC")
        self.generate_poc_btn.setEnabled(False)
        header_layout.addWidget(self.generate_poc_btn)
        
        self.dismiss_btn = QPushButton("Dismiss")
        self.dismiss_btn.setEnabled(False)
        header_layout.addWidget(self.dismiss_btn)
        
        layout.addLayout(header_layout)
        
        # Details
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        # Metadata
        meta_layout = QHBoxLayout()
        self.severity_label = QLabel()
        self.status_label = QLabel()
        self.confidence_label = QLabel()
        meta_layout.addWidget(QLabel("Severity:"))
        meta_layout.addWidget(self.severity_label)
        meta_layout.addWidget(QLabel("Status:"))
        meta_layout.addWidget(self.status_label)
        meta_layout.addWidget(QLabel("Confidence:"))
        meta_layout.addWidget(self.confidence_label)
        meta_layout.addStretch()
        details_layout.addLayout(meta_layout)
        
        # Description
        details_layout.addWidget(QLabel("<b>Description:</b>"))
        self.description_text = QTextEdit()
        self.description_text.setReadOnly(True)
        self.description_text.setMaximumHeight(100)
        details_layout.addWidget(self.description_text)
        
        # Attack vector
        details_layout.addWidget(QLabel("<b>Attack Vector:</b>"))
        self.attack_text = QTextEdit()
        self.attack_text.setReadOnly(True)
        self.attack_text.setMaximumHeight(80)
        details_layout.addWidget(self.attack_text)
        
        # Preconditions
        details_layout.addWidget(QLabel("<b>Preconditions:</b>"))
        self.preconditions_text = QTextEdit()
        self.preconditions_text.setReadOnly(True)
        self.preconditions_text.setMaximumHeight(60)
        details_layout.addWidget(self.preconditions_text)
        
        # Impact
        details_layout.addWidget(QLabel("<b>Impact:</b>"))
        self.impact_text = QTextEdit()
        self.impact_text.setReadOnly(True)
        self.impact_text.setMaximumHeight(60)
        details_layout.addWidget(self.impact_text)
        
        # POC Code
        details_layout.addWidget(QLabel("<b>POC Code:</b>"))
        self.poc_text = QPlainTextEdit()
        self.poc_text.setReadOnly(True)
        self.poc_text.setFont(QFont("Consolas", 9))
        self.poc_text.setStyleSheet("""
            QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
            }
        """)
        details_layout.addWidget(self.poc_text)
        
        details_layout.addStretch()
        scroll.setWidget(details_widget)
        layout.addWidget(scroll)
    
    def set_lead(self, lead: VulnerabilityLead):
        self.current_lead = lead
        
        self.title_label.setText(lead.title)
        
        # Set severity with color
        severity_color = SEVERITY_COLORS.get(lead.severity, "#808080")
        self.severity_label.setText(
            f'<span style="color: {severity_color}">{lead.severity.value}</span>'
        )
        
        # Set status with color
        status_color = STATUS_COLORS.get(lead.status, "#808080")
        self.status_label.setText(
            f'<span style="color: {status_color}">{lead.status.value}</span>'
        )
        
        self.confidence_label.setText(f"{lead.confidence:.0%}")
        
        self.description_text.setPlainText(lead.description)
        self.attack_text.setPlainText(lead.attack_vector)
        self.preconditions_text.setPlainText("\n".join(lead.preconditions))
        self.impact_text.setPlainText(lead.impact)
        self.poc_text.setPlainText(lead.foundry_poc or "No POC generated yet")
        
        # Enable/disable buttons
        self.generate_poc_btn.setEnabled(
            lead.status in (LeadStatus.RANKED, LeadStatus.TRIAGED)
        )
        self.dismiss_btn.setEnabled(lead.status != LeadStatus.DISMISSED)
    
    def clear(self):
        self.current_lead = None
        self.title_label.setText("Select a lead to view details")
        self.severity_label.clear()
        self.status_label.clear()
        self.confidence_label.clear()
        self.description_text.clear()
        self.attack_text.clear()
        self.preconditions_text.clear()
        self.impact_text.clear()
        self.poc_text.clear()
        self.generate_poc_btn.setEnabled(False)
        self.dismiss_btn.setEnabled(False)


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EVM Solidity Auditing Agent")
        self.setMinimumSize(1400, 900)
        
        # State
        self.current_session: Optional[Session] = None
        self.auditor: Optional[ContinuousAuditor] = None
        self.model_brain: Optional[ModelBrain] = None
        
        self._setup_ui()
        self._setup_menu()
        self._setup_toolbar()
        self._setup_statusbar()
        self._connect_signals()
        
        # Load saved sessions
        self._load_sessions()
    
    def _setup_ui(self):
        # Central widget with splitter
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        
        # Left panel - Project explorer
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Session selector
        session_group = QGroupBox("Session")
        session_layout = QHBoxLayout()
        self.session_combo = QComboBox()
        self.session_combo.setMinimumWidth(200)
        session_layout.addWidget(self.session_combo)
        
        self.new_session_btn = QPushButton("New")
        self.load_session_btn = QPushButton("Load")
        session_layout.addWidget(self.new_session_btn)
        session_layout.addWidget(self.load_session_btn)
        
        session_group.setLayout(session_layout)
        left_layout.addWidget(session_group)
        
        # Model selector
        model_group = QGroupBox("Model")
        model_layout = QHBoxLayout()
        self.model_combo = QComboBox()
        self.model_combo.addItems([
            "glm-4-plus",
            "glm-4",
            "glm-4-flash",
        ])
        model_layout.addWidget(self.model_combo)
        model_group.setLayout(model_layout)
        left_layout.addWidget(model_group)
        
        # Contracts tree
        contracts_group = QGroupBox("Contracts")
        contracts_layout = QVBoxLayout()
        self.contracts_tree = ContractTreeWidget()
        contracts_layout.addWidget(self.contracts_tree)
        contracts_group.setLayout(contracts_layout)
        left_layout.addWidget(contracts_group)
        
        # Progress
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_label)
        progress_group.setLayout(progress_layout)
        left_layout.addWidget(progress_group)
        
        main_layout.addWidget(left_panel, 2)
        
        # Middle panel - Tabs
        middle_panel = QTabWidget()
        
        # Leads tab
        leads_widget = QWidget()
        leads_layout = QVBoxLayout(leads_widget)
        
        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        filter_layout.addWidget(self.severity_filter)
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "new", "ranked", "triaged", "testing", "confirmed", "dismissed"])
        filter_layout.addWidget(self.status_filter)
        filter_layout.addStretch()
        leads_layout.addLayout(filter_layout)
        
        # Leads table
        self.leads_table = LeadsTableWidget()
        leads_layout.addWidget(self.leads_table)
        
        middle_panel.addTab(leads_widget, "Leads")
        
        # Lead detail tab
        self.lead_detail = LeadDetailWidget()
        middle_panel.addTab(self.lead_detail, "Lead Detail")
        
        # Source code tab
        self.source_view = QPlainTextEdit()
        self.source_view.setReadOnly(True)
        self.source_view.setFont(QFont("Consolas", 10))
        middle_panel.addTab(self.source_view, "Source Code")
        
        main_layout.addWidget(middle_panel, 5)
        
        # Right panel - Terminal and Chat
        right_panel = QTabWidget()
        
        # Terminal
        self.terminal = TerminalWidget()
        right_panel.addTab(self.terminal, "Terminal")
        
        # Chat with LLM
        chat_widget = QWidget()
        chat_layout = QVBoxLayout(chat_widget)
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Ask a question about the codebase...")
        self.chat_input.returnPressed.connect(self._send_chat)
        chat_layout.addWidget(self.chat_history)
        chat_layout.addWidget(self.chat_input)
        right_panel.addTab(chat_widget, "AI Chat")
        
        main_layout.addWidget(right_panel, 3)
    
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
        
        export_action = QAction("&Export Report...", self)
        export_action.triggered.connect(self._export_report)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Analysis menu
        analysis_menu = menubar.addMenu("&Analysis")
        
        run_slither = QAction("Run &Slither", self)
        run_slither.triggered.connect(self._run_slither)
        analysis_menu.addAction(run_slither)
        
        run_analysis = QAction("Run &Full Analysis", self)
        run_analysis.setShortcut(QKeySequence("Ctrl+Shift+A"))
        run_analysis.triggered.connect(self._run_full_analysis)
        analysis_menu.addAction(run_analysis)
        
        analysis_menu.addSeparator()
        
        stop_action = QAction("&Stop Analysis", self)
        stop_action.triggered.connect(self._stop_analysis)
        analysis_menu.addAction(stop_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        clear_terminal = QAction("Clear &Terminal", self)
        clear_terminal.triggered.connect(self.terminal.clear_log)
        view_menu.addAction(clear_terminal)
    
    def _setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        
        # Start analysis button
        self.start_btn = QPushButton("▶ Start Audit")
        self.start_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 5px 15px;")
        self.start_btn.clicked.connect(self._run_full_analysis)
        toolbar.addWidget(self.start_btn)
        
        toolbar.addSeparator()
        
        # Stop button
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.setStyleSheet("background-color: #f44336; color: white; padding: 5px 15px;")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_analysis)
        toolbar.addWidget(self.stop_btn)
        
        toolbar.addSeparator()
        
        # Generate report button
        report_btn = QPushButton("📄 Generate Report")
        report_btn.clicked.connect(self._export_report)
        toolbar.addWidget(report_btn)
    
    def _setup_statusbar(self):
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready")
    
    def _connect_signals(self):
        # Session buttons
        self.new_session_btn.clicked.connect(self._new_session)
        self.load_session_btn.clicked.connect(self._load_selected_session)
        self.session_combo.currentIndexChanged.connect(self._on_session_changed)
        
        # Contract tree
        self.contracts_tree.contract_selected.connect(self._on_contract_selected)
        
        # Leads table
        self.leads_table.lead_selected.connect(self._on_lead_selected)
        self.leads_table.lead_double_clicked.connect(self._on_lead_double_clicked)
        
        # Lead detail
        self.lead_detail.generate_poc_btn.clicked.connect(self._generate_poc)
        self.lead_detail.dismiss_btn.clicked.connect(self._dismiss_lead)
    
    # === Session Management ===
    
    def _load_sessions(self):
        """Load available sessions into combo box"""
        sessions = session_manager.list_sessions()
        self.session_combo.clear()
        self.session_combo.addItem("-- Select Session --", None)
        
        for session in sessions:
            self.session_combo.addItem(
                f"{session['name']} ({session['id']})",
                session['id']
            )
    
    def _new_session(self):
        """Create a new session"""
        dialog = NewSessionDialog(self)
        if dialog.exec() == QDialog.Accepted:
            data = dialog.get_session_data()
            
            if not data['name'] or not data['path']:
                QMessageBox.warning(
                    self, "Invalid Input",
                    "Please provide a name and project path."
                )
                return
            
            # Create session
            self.current_session = session_manager.create_session(
                name=data['name'],
                project_path=data['path'],
                github_url=data['github_url'] or None
            )
            
            # Set API keys
            if data['etherscan_key']:
                self.current_session.etherscan_api_key = data['etherscan_key']
            if data['alchemy_key']:
                self.current_session.alchemy_api_key = data['alchemy_key']
            
            session_manager.save_current_session()
            
            # Parse contracts
            self._parse_project()
            
            # Refresh UI
            self._load_sessions()
            self._update_ui_for_session()
            
            self.terminal.log_success(f"Created session: {data['name']}")
    
    def _load_selected_session(self):
        """Load the selected session"""
        session_id = self.session_combo.currentData()
        if session_id:
            self.current_session = session_manager.load_session(session_id)
            if self.current_session:
                self._update_ui_for_session()
                self.terminal.log_success(f"Loaded session: {self.current_session.name}")
    
    def _on_session_changed(self, index: int):
        """Handle session combo change"""
        session_id = self.session_combo.currentData()
        if session_id and session_id != getattr(self.current_session, 'id', None):
            self.current_session = session_manager.load_session(session_id)
            if self.current_session:
                self._update_ui_for_session()
    
    def _update_ui_for_session(self):
        """Update UI elements for current session"""
        if not self.current_session:
            return
        
        # Update contracts tree
        self.contracts_tree.load_contracts(self.current_session.contracts)
        
        # Update leads table
        self.leads_table.load_leads(self.current_session.leads)
        
        # Update status
        self.statusbar.showMessage(
            f"Session: {self.current_session.name} | "
            f"Contracts: {len(self.current_session.contracts)} | "
            f"Leads: {len(self.current_session.leads)}"
        )
    
    # === Project Parsing ===
    
    def _parse_project(self):
        """Parse the project contracts"""
        if not self.current_session:
            return
        
        self.terminal.log_info("Parsing contracts...")
        self.statusbar.showMessage("Parsing contracts...")
        
        project_path = Path(self.current_session.project_path)
        results = solidity_parser.parse_directory(project_path)
        
        for result in results:
            for contract in result.contracts:
                self.current_session.contracts.append(contract)
                self.terminal.log_info(f"Found contract: {contract.name}")
        
        session_manager.save_current_session()
        self._update_ui_for_session()
        
        self.terminal.log_success(f"Parsed {len(self.current_session.contracts)} contracts")
    
    def _open_project(self):
        """Open a project directory"""
        path = QFileDialog.getExistingDirectory(
            self, "Open Project Directory"
        )
        if path:
            # Create a new session for this project
            self.current_session = session_manager.create_session(
                name=Path(path).name,
                project_path=path
            )
            self._parse_project()
            self._load_sessions()
    
    # === Analysis ===
    
    def _run_slither(self):
        """Run Slither analysis"""
        if not self.current_session or not self.current_session.contracts:
            QMessageBox.warning(self, "No Session", "Please load a session first.")
            return
        
        self.terminal.log_info("Running Slither analysis...")
        
        try:
            for contract in self.current_session.contracts:
                leads = slither_analyzer.analyze(Path(contract.file_path))
                for lead in leads:
                    self.current_session.leads.append(lead)
                    self.terminal.log_info(f"Found: {lead.title}")
            
            session_manager.save_current_session()
            self._update_ui_for_session()
            
            self.terminal.log_success(
                f"Slither found {len(self.current_session.leads)} leads"
            )
        except Exception as e:
            self.terminal.log_error(f"Slither error: {e}")
    
    def _run_full_analysis(self):
        """Run full auditing process"""
        if not self.current_session:
            QMessageBox.warning(self, "No Session", "Please create or load a session first.")
            return
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self.terminal.log_info("Starting full audit...")
        
        # Initialize model brain
        llm_client = LLMClient()
        self.model_brain = ModelBrain(llm_client, self.model_combo.currentText())
        
        # Create auditor
        self.auditor = ContinuousAuditor(
            session=self.current_session,
            model_brain=self.model_brain,
            slither_analyzer=slither_analyzer,
            z3_executor=z3_executor,
            session_manager=session_manager,
        )
        
        # Set up callbacks
        self.auditor.on_progress_update = self._on_audit_progress
        self.auditor.on_lead_found = self._on_lead_found
        self.auditor.on_bug_confirmed = self._on_bug_confirmed
        self.auditor.on_phase_complete = self._on_phase_complete
        
        # Run in background thread
        self.worker = AsyncWorker(self.auditor.run_audit())
        self.worker.finished.connect(self._on_audit_finished)
        self.worker.error.connect(self._on_audit_error)
        self.worker.start()
    
    def _stop_analysis(self):
        """Stop the current analysis"""
        if self.auditor:
            self.auditor.stop()
            self.terminal.log_warning("Stopping analysis...")
    
    def _on_audit_progress(self, progress):
        """Handle audit progress update"""
        self.progress_bar.setValue(int(progress.total_progress * 100))
        self.progress_label.setText(f"{progress.phase.value}: {progress.current_task}")
    
    def _on_lead_found(self, lead: VulnerabilityLead):
        """Handle new lead found"""
        self.terminal.log_info(f"Lead found: {lead.title} ({lead.severity.value})")
        self._update_ui_for_session()
    
    def _on_bug_confirmed(self, lead: VulnerabilityLead):
        """Handle bug confirmation"""
        self.terminal.log_success(f"BUG CONFIRMED: {lead.title}")
        self._update_ui_for_session()
    
    def _on_phase_complete(self, phase):
        """Handle phase completion"""
        self.terminal.log_info(f"Phase completed: {phase.value}")
    
    def _on_audit_finished(self, result):
        """Handle audit completion"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        if result:
            self.terminal.log_success("Audit completed successfully!")
        else:
            self.terminal.log_warning("Audit was stopped or failed")
        
        self._update_ui_for_session()
    
    def _on_audit_error(self, error: str):
        """Handle audit error"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.terminal.log_error(f"Audit error: {error}")
    
    # === Selection Handlers ===
    
    def _on_contract_selected(self, identifier: str):
        """Handle contract/function selection"""
        if '.' in identifier:
            contract_name, func_name = identifier.split('.')
            # Find function source
            for contract in self.current_session.contracts:
                if contract.name == contract_name:
                    try:
                        source = Path(contract.file_path).read_text()
                        self.source_view.setPlainText(source)
                    except Exception:
                        pass
                    break
        else:
            # Show contract source
            for contract in self.current_session.contracts:
                if contract.name == identifier:
                    try:
                        source = Path(contract.file_path).read_text()
                        self.source_view.setPlainText(source)
                    except Exception:
                        pass
                    break
    
    def _on_lead_selected(self, lead_id: str):
        """Handle lead selection"""
        for lead in self.current_session.leads:
            if lead.id == lead_id:
                self.lead_detail.set_lead(lead)
                break
    
    def _on_lead_double_clicked(self, lead_id: str):
        """Handle lead double-click"""
        self._on_lead_selected(lead_id)
        # Switch to detail tab
        tab_widget = self.lead_detail.parent()
        if isinstance(tab_widget, QTabWidget):
            tab_widget.setCurrentWidget(self.lead_detail)
    
    # === Lead Actions ===
    
    def _generate_poc(self):
        """Generate POC for selected lead"""
        lead = self.lead_detail.current_lead
        if not lead:
            return
        
        self.terminal.log_info(f"Generating POC for: {lead.title}")
        
        # Find contract
        contract = None
        for c in self.current_session.contracts:
            if c.name in lead.affected_contracts:
                contract = c
                break
        
        if not contract:
            self.terminal.log_error("Could not find affected contract")
            return
        
        # Run async POC generation
        async def gen_poc():
            source = Path(contract.file_path).read_text()
            return await self.model_brain.generate_foundry_poc(lead, contract, source)
        
        self.poc_worker = AsyncWorker(gen_poc())
        self.poc_worker.finished.connect(
            lambda poc: self._on_poc_generated(lead, poc)
        )
        self.poc_worker.start()
    
    def _on_poc_generated(self, lead: VulnerabilityLead, poc: str):
        """Handle POC generation complete"""
        lead.foundry_poc = poc
        session_manager.save_current_session()
        self.lead_detail.set_lead(lead)
        self.terminal.log_success("POC generated")
    
    def _dismiss_lead(self):
        """Dismiss the selected lead"""
        lead = self.lead_detail.current_lead
        if lead:
            lead.status = LeadStatus.DISMISSED
            lead.false_positive = True
            session_manager.save_current_session()
            self._update_ui_for_session()
            self.terminal.log_info(f"Dismissed lead: {lead.title}")
    
    # === Chat ===
    
    def _send_chat(self):
        """Send chat message to LLM"""
        question = self.chat_input.text().strip()
        if not question or not self.model_brain:
            return
        
        self.chat_history.append(f"<b>You:</b> {question}")
        self.chat_input.clear()
        
        # Get context
        context = ""
        if self.current_session:
            contracts = [c.name for c in self.current_session.contracts]
            context = f"Analyzing contracts: {', '.join(contracts)}"
        
        async def ask():
            return await self.model_brain.ask_question(question, context)
        
        self.chat_worker = AsyncWorker(ask())
        self.chat_worker.finished.connect(
            lambda response: self.chat_history.append(
                f"<b>Assistant:</b> {response}<br>"
            )
        )
        self.chat_worker.start()
    
    # === Export ===
    
    def _export_report(self):
        """Export audit report"""
        if not self.current_session:
            QMessageBox.warning(self, "No Session", "Please load a session first.")
            return
        
        confirmed_leads = [l for l in self.current_session.leads if l.confirmed]
        if not confirmed_leads:
            QMessageBox.information(
                self, "No Confirmed Bugs",
                "No confirmed vulnerabilities to report."
            )
            return
        
        # Ask for format
        formats = ["Markdown (.md)", "PDF (.pdf)", "JSON (.json)"]
        format_choice, ok = QInputDialog.getItem(
            self, "Export Format", "Select export format:", formats, 0, False
        )
        
        if not ok:
            return
        
        format_map = {
            "Markdown (.md)": "markdown",
            "PDF (.pdf)": "pdf",
            "JSON (.json)": "json",
        }
        
        # Generate reports
        reports = []
        for lead in confirmed_leads:
            report = report_generator.generate_report(lead, lead.foundry_poc or "")
            reports.append(report)
        
        # Save
        path = report_generator.generate_session_report(
            self.current_session.to_dict(),
            reports,
            format=format_map[format_choice]
        )
        
        if path:
            self.terminal.log_success(f"Report saved: {path}")
            QMessageBox.information(
                self, "Report Generated",
                f"Report saved to:\n{path}"
            )
        else:
            self.terminal.log_error("Failed to generate report")


def main():
    """Application entry point"""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Dark theme palette (optional)
    from PySide6.QtGui import QPalette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
    app.setPalette(palette)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
