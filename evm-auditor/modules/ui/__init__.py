"""UI Module - PySide6 Desktop Interface"""

# Import only if PySide6 is available
try:
    from .main_window import MainWindow, TerminalWidget, ContractTreeWidget, LeadsTableWidget
    __all__ = ['MainWindow', 'TerminalWidget', 'ContractTreeWidget', 'LeadsTableWidget']
except ImportError:
    __all__ = []
