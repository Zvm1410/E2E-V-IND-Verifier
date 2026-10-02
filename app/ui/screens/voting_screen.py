from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QScrollArea, QSizePolicy, QVBoxLayout, QWidget

from app.ui.widgets.candidate_card import CandidateCard
from app.ui.widgets.header import Header, StatusBar


class VotingScreen(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window

        root = QVBoxLayout()
        root.setContentsMargins(48, 0, 48, 36)
        root.setSpacing(20)

        self.header = Header("SELECT YOUR CANDIDATE", "Tap one name to continue")
        self.status = StatusBar()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self.container = QWidget()
        self.container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.container.setMaximumWidth(535)
        self.container_layout = QVBoxLayout()
        self.container_layout.setSpacing(16)
        self.container_layout.setContentsMargins(0, 0, 0, 0)
        self.container_layout.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.container.setLayout(self.container_layout)

        scroll.setWidget(self.container)
        root.addWidget(self.header)
        root.addWidget(self.status)
        root.addWidget(scroll)
        self.setLayout(root)

    def rebuild_candidates(self) -> None:
        while self.container_layout.count():
            item = self.container_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        for candidate in self.window.config.candidates:
            card = CandidateCard(candidate)
            card.clicked.connect(self.window.select_candidate)
            self.container_layout.addWidget(card)

    def refresh_status(self) -> None:
        poll = self.window.poll_state
        session = poll.current_ballot
        register = poll.poll_register()
        self.status.set_booth(self.window.config.booth_id)
        self.status.set_serial(session.serial if session else poll.next_serial)
        self.status.set_counted(register["ballots_counted"], register["ballots_issued"])
