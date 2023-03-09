import { Component } from '@angular/core';
import { faSpinner } from '@fortawesome/free-solid-svg-icons';
/** CURRENTLY UNUSED review page */
@Component({
  selector: 'app-review',
  templateUrl: './review.component.html',
  styleUrls: ['./review.component.css']
})
export class ReviewComponent {
  /** FontAwesome Icon */
  faSpinner = faSpinner;
}
