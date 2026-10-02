from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QCursor
from PyQt6.QtWidgets import (
    QMainWindow, QMessageBox, QProgressDialog, QStackedWidget,
)
from app.models.candidate import Candidate
from app.models.election_config import ElectionConfig
from app.services.ballot_service import BallotService
from app.services.election_loader import ElectionConfigError, load_election_config
from app.services.poll_state import PollState
from app.ui.screens.admin_screen import AdminScreen
from app.ui.screens.confirmation_screen import ConfirmationScreen
from app.ui.screens.logo_screen import LogoScreen
from app.ui.screens.splash_screen import SplashScreen
from app.ui.screens.voting_screen import VotingScreen
from app.ui.theme.colors import SCREEN_HEIGHT, SCREEN_WIDTH


class MainWindow(QMainWindow):
    def __init__(self, config_path: str = "config/election.json", kiosk: bool = True):
        super().__init__()

        self.kiosk = kiosk
        self.config_path = config_path
        self.poll_state = PollState()
        self.config: ElectionConfig
        self.ballot_service: BallotService
        self.selected_candidate: Candidate | None = None

        try:
            self.config = load_election_config(config_path)
        except ElectionConfigError as exc:
            QMessageBox.critical(self, "Configuration Error", str(exc))
            raise SystemExit(1) from exc

        self.ballot_service = BallotService(self.config, self.poll_state)

        self.setWindowTitle(f"{self.config.election_id} — {self.config.booth_id}")
        self._apply_screen_fit()

        self.stack = QStackedWidget()
        self.splash_screen = SplashScreen(self)
        self.voting_screen = VotingScreen(self)
        self.confirmation_screen = ConfirmationScreen(self)
        self.logo_screen = LogoScreen(self)
        self.admin_screen = AdminScreen(self)

        for screen in (
            self.splash_screen,
            self.voting_screen,
            self.confirmation_screen,
            self.logo_screen,
            self.admin_screen,
        ):
            self.stack.addWidget(screen)

        self.setCentralWidget(self.stack)
        self.splash_screen.bind_config(self.config)
        self.voting_screen.rebuild_candidates()
        self.show_screen(self.splash_screen)

        if kiosk:
            self.enter_kiosk_mode()

    def _apply_screen_fit(self) -> None:
        screen = self.screen().availableGeometry()

        if self.kiosk:
            scale = min(screen.width() / SCREEN_WIDTH, screen.height() / SCREEN_HEIGHT)
            scale = max(0.35, min(1.0, scale))

            target_w = max(1, int(round(SCREEN_WIDTH * scale)))
            target_h = max(1, int(round(SCREEN_HEIGHT * scale)))
        else:
            screen_ratio = screen.width() / max(1, screen.height())
            landscape_target_w = min(int(screen.width() * 0.76), 1500)
            landscape_target_h = min(int(screen.height() * 0.82), 980)

            if screen_ratio >= 1.35:
                target_w = max(900, landscape_target_w)
                target_h = max(700, landscape_target_h)
            else:
                target_w = max(1, int(round(SCREEN_WIDTH * 0.7)))
                target_h = max(1, int(round(SCREEN_HEIGHT * 0.7)))

        self.setMinimumSize(target_w, target_h)
        self.setMaximumSize(target_w, target_h)
        self.resize(target_w, target_h)

        x = max(0, (screen.width() - target_w) // 2)
        y = max(0, (screen.height() - target_h) // 2)
        self.setGeometry(x, y, target_w, target_h)

    def enter_kiosk_mode(self) -> None:
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
        )
        self._apply_screen_fit()
        self.setCursor(QCursor(Qt.CursorShape.BlankCursor))
        self.show()

    def show_screen(self, screen) -> None:
        if hasattr(screen, "refresh_status"):
            screen.refresh_status()
        self.stack.setCurrentWidget(screen)

    def begin_voting(self) -> None:
        self.poll_state.begin_ballot()
        self.show_screen(self.voting_screen)

    def select_candidate(self, candidate: Candidate) -> None:
        self.selected_candidate = candidate
        self.poll_state.mark_selection(candidate.index)
        self.confirmation_screen.set_candidate(candidate)
        self.show_screen(self.confirmation_screen)

    def return_to_voting(self) -> None:
        self.show_screen(self.voting_screen)

    def cast_vote(self) -> None:
        if self.selected_candidate is None:
            return

        # Real 3072-bit ElGamal + validity proofs + sum-to-one proof
        # takes ~5 seconds on Mac, ~20 seconds on Pi. Show a modal
        # spinner so voters see feedback instead of a frozen UI.
        dlg = QProgressDialog(
            "Encrypting your ballot securely...\n"
            "Please do not touch the screen.",
            None,        # no cancel button
            0, 0,        # indeterminate spinner
            self,
        )
        dlg.setWindowTitle("Casting Ballot")
        dlg.setWindowModality(Qt.WindowModality.ApplicationModal)
        dlg.setCancelButton(None)
        dlg.setMinimumDuration(0)
        dlg.setAutoClose(False)
        dlg.show()

        # Give Qt one paint cycle to render the dialog before we block
        # on the crypto call.
        QTimer.singleShot(50, lambda: self._do_cast(dlg))

    def _do_cast(self, dlg) -> None:
        try:
            self.poll_state.confirm_selection()
            artifacts = self.ballot_service.encrypt_and_prove(
                self.selected_candidate.index
            )
            self.ballot_service.append_ballot(artifacts)
            self.logo_screen.show_logo(self.selected_candidate.index)
            self.show_screen(self.logo_screen)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(
                self, "Ballot Cast Failed",
                f"Encryption or board append failed:\n{exc}",
            )
        finally:
            dlg.close()
    def finish_voting_cycle(self) -> None:
        self.poll_state.finish_ballot()
        self.selected_candidate = None
        self.splash_screen.refresh_status()
        self.show_screen(self.splash_screen)

    def show_admin(self) -> None:
        self.admin_screen.refresh()
        self.show_screen(self.admin_screen)

    def hide_admin(self) -> None:
        self.show_screen(self.splash_screen)

    def keyPressEvent(self, event) -> None:
        if (
            event.key() == Qt.Key.Key_A
            and event.modifiers()
            == (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
        ):
            current = self.stack.currentWidget()
            if current is self.admin_screen:
                self.hide_admin()
            else:
                self.show_admin()
            return

        if (
            self.kiosk
            and event.key() == Qt.Key.Key_Escape
            and event.modifiers()
            == (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier)
        ):
            self.close()
            return

        super().keyPressEvent(event)
