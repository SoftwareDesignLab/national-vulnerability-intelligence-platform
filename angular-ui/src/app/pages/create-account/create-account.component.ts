import { Component } from '@angular/core';
import { NgForm } from '@angular/forms';
import { faKey, faLock, faTimes } from '@fortawesome/free-solid-svg-icons';
import { AuthService } from 'src/app/services/Auth/auth-service.service';

/** Create account page */
@Component({
  selector: 'app-create-account',
  templateUrl: './create-account.component.html',
  styleUrls: ['./create-account.component.css']
})
export class CreateAccountComponent {
  /** FontAwesome Icons */
  faKey = faKey;
  faLock = faLock;
  faTimes = faTimes;
  /** Variables to hold form state */
  dataLoading = false;
  credentials = {
    username: '',
    password: '',
    repeatPassword: '',
    fname: '',
    lname: '',
    email: ''
  }

  /**
   * create account constructor
   * @param authService access create account endpoint
   */
  constructor(private authService: AuthService) { }

  /** give ngForm to api endpoint to create user based on input html form */
  createAccount(f: NgForm) {
    if(f.value.password === f.value.repeatPassword){
      this.authService.createUser(f.value);
    } else {
      this.passwordError();
    }
  }
  /** displays error message is password and repeatPassword don't match */
  passwordError(){
    var passwordError = document.getElementById('registrationMessage') as HTMLDivElement;
    var formSpacing = document.getElementById('regForm') as HTMLDivElement;
    passwordError.style.display = 'block';
    formSpacing.style.marginTop = "6em";
  }

}
