from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout

from app.models.candidate import Candidate
from app.ui.theme.colors import GREEN, LIGHT_BLUE, ORANGE
from app.ui.widgets.logo import party_logo_pixmap


class CandidateCard(QFrame):
    clicked = pyqtSignal(object)

    def __init__(self, candidate: Candidate):
        super().__init__()
        self.candidate = candidate
        self.setProperty("class", "card")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(150)

        layout = QHBoxLayout()
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(24)

        badge = QLabel()
        badge.setFixedSize(72, 72)
        badge.setPixmap(party_logo_pixmap(candidate.index, 72))
        badge.setScaledContents(True)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(6)
        name = QLabel(candidate.display_name)
        name.setStyleSheet("font-size: 32px; font-weight: 700;")
        code = QLabel(candidate.candidate_id)
        code.setStyleSheet("font-size: 20px; color: #5A6B75;")
        text_layout.addWidget(name)
        text_layout.addWidget(code)

        select = QLabel("SELECT")
        select.setAlignment(Qt.AlignmentFlag.AlignCenter)
        select.setFixedSize(160, 64)
        select.setStyleSheet(
            f"""
            background: {GREEN};
            color: white;
            border-radius: 16px;
            font-size: 22px;
            font-weight: 700;
            """
        )

        layout.addWidget(badge)
        layout.addLayout(text_layout, stretch=1)
        layout.addWidget(select)
        self.setLayout(layout)

        if candidate.candidate_id == "NOTA":
            self.setStyleSheet(
                f"""
                QFrame {{
                    background: #FFF7F0;
                    border: 2px solid {ORANGE};
                    border-radius: 20px;
                }}
                """
            )

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.candidate)
        super().mousePressEvent(event)
