from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QLabel, QPushButton, QVBoxLayout, QWidget

from app.models.candidate import Candidate
from app.ui.theme.colors import GREEN, LIGHT_BLUE
from app.ui.widgets.header import Header, StatusBar


class ConfirmationScreen(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.candidate: Candidate | None = None

        root = QVBoxLayout()
        root.setContentsMargins(48, 0, 48, 48)
        root.setSpacing(24)

        self.header = Header("CONFIRM YOUR SELECTION")
        self.status = StatusBar()

        prompt = QLabel("Please verify your choice before casting.")
        prompt.setProperty("class", "subtitle")
        prompt.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setProperty("class", "card")
        card_layout = QVBoxLayout()
        card_layout.setContentsMargins(36, 36, 36, 36)
        card_layout.setSpacing(12)

        self.index_label = QLabel("")
        self.index_label.setStyleSheet(
            f"font-size: 24px; color: #5A6B75; background: {LIGHT_BLUE}; "
            "border-radius: 12px; padding: 12px;"
        )
        self.index_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.name_label = QLabel("")
        self.name_label.setStyleSheet("font-size: 48px; font-weight: 700;")
        self.name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.code_label = QLabel("")
        self.code_label.setProperty("class", "hint")
        self.code_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card_layout.addWidget(self.index_label)
        card_layout.addWidget(self.name_label)
        card_layout.addWidget(self.code_label)
        card.setLayout(card_layout)

        confirm = QPushButton("CONFIRM AND CAST VOTE")
        confirm.setFixedHeight(96)
        confirm.clicked.connect(self.window.cast_vote)

        back = QPushButton("GO BACK")
        back.setProperty("class", "secondary")
        back.setFixedHeight(84)
        back.clicked.connect(self.window.return_to_voting)

        root.addWidget(self.header)
        root.addWidget(self.status)
        root.addStretch()
        root.addWidget(prompt)
        root.addWidget(card)
        root.addStretch()
        root.addWidget(back)
        root.addWidget(confirm)
        self.setLayout(root)

    def set_candidate(self, candidate: Candidate) -> None:
        self.candidate = candidate
        self.index_label.setText(f"Candidate #{candidate.index + 1}")
        self.name_label.setText(candidate.display_name)
        self.code_label.setText(candidate.candidate_id)
        if candidate.candidate_id == "NOTA":
            self.name_label.setStyleSheet(f"font-size: 48px; font-weight: 700; color: {GREEN};")

    def refresh_status(self) -> None:
        poll = self.window.poll_state
        session = poll.current_ballot
        register = poll.poll_register()
        self.status.set_booth(self.window.config.booth_id)
        self.status.set_serial(session.serial if session else None)
        self.status.set_counted(register["ballots_counted"], register["ballots_issued"])
