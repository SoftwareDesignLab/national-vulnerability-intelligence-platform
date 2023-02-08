import { Component } from '@angular/core';
import { NgForm } from '@angular/forms';
import { AuthService } from 'src/app/services/Auth/auth-service.service';
import { faTimes, faKey, faLock } from '@fortawesome/free-solid-svg-icons';
import { FuncsService } from 'src/app/services/Funcs/funcs.service';

@Component({
  selector: 'nvip-login-panel',
  templateUrl: './login-panel.component.html',
  styleUrls: ['./login-panel.component.css'],
})
export class LoginPanelComponent {
  /** Font Awesome Icons */
  faTimes = faTimes;
  faKey = faKey;
  faLock = faLock;
  /** Variables to hold credentials state in form */
  dataLoading = false;
  credentials = {
    username: '',
    password: '',
  };

  /**
   * login panel constructor
   * @param authService - authentication service singleton - access auth api calls
   * @param funcs - access globally init functions
   */
  constructor(private authService: AuthService, private funcs: FuncsService) {}

  /** access login endpoint from loginServlet */
  login(f: NgForm) {
    this.authService.onLogin({
      userName: f.value.username,
      passwordHash: f.value.password,
    });
  }

  /** handle close login */
  clearListener() {
    this.funcs.closeLogin();
  }
}
