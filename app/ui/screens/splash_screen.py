from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from app.models.election_config import ElectionConfig
from app.ui.theme.colors import LIGHT_BLUE
from app.ui.widgets.header import Header, StatusBar


class SplashScreen(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window

        root = QVBoxLayout()
        root.setContentsMargins(48, 0, 48, 48)
        root.setSpacing(24)

        self.header = Header()
        self.status = StatusBar()

        hero = QLabel("Ready to Vote")
        hero.setProperty("class", "title")
        hero.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("Tap below when the poll officer instructs you to begin.")
        subtitle.setProperty("class", "subtitle")
        subtitle.setWordWrap(True)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        info = QLabel("")
        info.setProperty("class", "hint")
        info.setWordWrap(True)
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info.setStyleSheet(
            f"""
            background: {LIGHT_BLUE};
            border-radius: 18px;
            padding: 24px;
            font-size: 24px;
            """
        )
        self.info = info

        start = QPushButton("START VOTING")
        start.setFixedHeight(96)
        start.clicked.connect(self.window.begin_voting)

        root.addWidget(self.header)
        root.addWidget(self.status)
        root.addStretch()
        root.addWidget(hero)
        root.addWidget(subtitle)
        root.addWidget(info)
        root.addStretch()
        root.addWidget(start)
        self.setLayout(root)

    def bind_config(self, config: ElectionConfig) -> None:
        self.status.set_booth(config.booth_id)
        self.info.setText(
            f"Election: {config.election_id}\n"
            f"Booth: {config.booth_id}\n"
            f"Candidates: {config.candidate_count}"
        )

    def refresh_status(self) -> None:
        poll = self.window.poll_state
        register = poll.poll_register()
        self.status.set_counted(register["ballots_counted"], register["ballots_issued"])
        self.status.set_serial(None)
