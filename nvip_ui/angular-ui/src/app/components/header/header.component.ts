import { Component } from '@angular/core';
import { AuthService } from 'src/app/services/Auth/auth-service.service';
import { faSignOut } from '@fortawesome/free-solid-svg-icons';
import { Router } from '@angular/router';
import { FuncsService } from 'src/app/services/Funcs/funcs.service';
/** Header component */
@Component({
  selector: 'nvip-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css'],
})
export class HeaderComponent {
  faSignOut = faSignOut;
  constructor(private authService: AuthService, private router: Router, private funcs: FuncsService) {}

  /** legacy AngularJS openLogin function that uses HTML styling to overlay 
   * login panel over current page and displays to user 
   */
  openLogin() {
    this.authService.isAuthenticated();
    var loginPanel = document.getElementById('loginPanel') as HTMLDivElement;
    var nvipContent = document.getElementById('nvipContent') as HTMLDivElement;
    var loginMessage = document.getElementById(
      'loginMessage'
    ) as HTMLDivElement;
    var loginForm = document.getElementById('loginForm') as HTMLDivElement;

    loginPanel.style.display = 'block';
    loginPanel.style.visibility = 'visible';
    loginPanel.style.opacity = '1';
    nvipContent.style.filter = 'blur(100px)';
    loginMessage.style.display = 'none';
    loginForm.style.marginTop = '4em';
  }

  /** ensure user is logged in before accessing a certain page */
  isLoggedIn(): boolean {
    return this.authService.isAuthenticated();
  }

  /** show first name of user credentials on header */
  getFirstName(): string | undefined {
    return this.authService.get()?.firstName;
  }

  /** log out user triggered by log out button icon on far right */
  logOut() {
    this.authService.logout();
    this.router.navigate(['']);
  }

  /** navigate to a certain page */
  goTo(link: any) {
    if (this.isLoggedIn()) {
      this.router.navigate(link);
    } else this.openLogin();
  }

  /** Links that do not require login to navigate to */
  goToSafely(link: any) {
    this.router.navigate(link);
    this.funcs.closeLogin();
  }
}
