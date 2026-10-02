from PyQt6.QtWidgets import QFrame, QLabel, QVBoxLayout

from app.ui.theme.colors import GREEN, LIGHT_BLUE, ORANGE


class StatCard(QFrame):
    def __init__(self, caption: str, accent: str = LIGHT_BLUE):
        super().__init__()
        self.setProperty("class", "stat-card")
        self.setMinimumHeight(120)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(8)

        self.caption = QLabel(caption)
        self.caption.setStyleSheet("font-size: 20px; color: #5A6B75;")

        self.value = QLabel("0")
        self.value.setStyleSheet(
            f"font-size: 40px; font-weight: 700; color: {accent};"
        )

        layout.addWidget(self.caption)
        layout.addWidget(self.value)
        self.setLayout(layout)

    def set_value(self, value: str) -> None:
        self.value.setText(value)


class PollRegisterPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setProperty("class", "panel")

        layout = QVBoxLayout()
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Poll Register")
        title.setProperty("class", "section")
        title.setStyleSheet("font-size: 30px; font-weight: 700;")

        cards = QVBoxLayout()
        cards.setSpacing(12)
        self.issued = StatCard("Ballots Issued", ORANGE)
        self.spoiled = StatCard("Ballots Spoiled", LIGHT_BLUE)
        self.counted = StatCard("Ballots Counted", GREEN)
        cards.addWidget(self.issued)
        cards.addWidget(self.spoiled)
        cards.addWidget(self.counted)

        layout.addWidget(title)
        layout.addLayout(cards)
        self.setLayout(layout)

    def update_counts(self, issued: int, spoiled: int, counted: int) -> None:
        self.issued.set_value(str(issued))
        self.spoiled.set_value(str(spoiled))
        self.counted.set_value(str(counted))
