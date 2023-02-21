import { Injectable } from '@angular/core';
import { ApiService } from '../Api/api-service.service';
import { CookieService } from '../Cookie/cookie.service';

/* Related Interfaces */

/** user credentials from login form */
export interface AuthCredentials {
  userName: string;
  passwordHash: string;
}

/** User session - containing valuable information on who's logged in
 * and how elevated their privileges are
 */
export interface Session {
  userID: number;
  userName: string;
  roleId: number;
  firstName: string;
  token: string;
  expirationDate: object;
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {

  /**
   * Authentication service constructor
   * @param api access login endpoints
   * @param cookieService access browser cookie
   */
  constructor(private api: ApiService, private cookieService: CookieService) {}

  /** establish a session on a successful user login */
  onLogin(credentials: AuthCredentials) {
    this.api
      .login({
        userName: credentials.userName,
        passwordHash: credentials.passwordHash,
      })
      .subscribe({
        next: (res) => {
          var response = res as Session;
          var session: Session = {
            userID: response.userID,
            userName: response.userName,
            roleId: response.roleId,
            firstName: response.firstName,
            token: response.token,
            expirationDate: response.expirationDate
          }
          this.cookieService.put('nvip_user', session)
        },
        error: (e) => {
          alert(`Error ${e.status}: ${e.statusText}`)
          console.log(e); return false
        },
        complete: () => {return true},
      });
  }

  /** access login servlet endpoint to create user account */
  createUser(credentials: object) {
    this.api.createAccount(credentials, (res) => {alert("Your account is Created!")} );
  }

  /** check for login by accessing browser cookie */
  isAuthenticated() {
    const cookie = this.cookieService.get('nvip_user');
    return  cookie !== undefined && cookie !== null && Object.keys(cookie).length > 0 ;
  }

  /** access browser cookie of logged in user */
  get() {
    return this.cookieService.get('nvip_user');
  }

  /** remove cookie from browser, redirect user */
  logout() {
    this.cookieService.remove('nvip_user');
  }
}
