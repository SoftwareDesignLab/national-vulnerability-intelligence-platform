import { Component } from '@angular/core';
import { faSpinner, faAngleRight, faAngleLeft, faSearch, faTimesCircle } from '@fortawesome/free-solid-svg-icons';
/** CURRENTLY UNUSED Daily page */
@Component({
  selector: 'app-daily',
  templateUrl: './daily.component.html',
  styleUrls: ['./daily.component.css']
})
export class DailyComponent {
  /** FontAwesome Icons */
  faSpinner = faSpinner;
  faAngleRight = faAngleRight;
  faAngleLeft = faAngleLeft;
  faSearch = faSearch;
  faTimesCircle = faTimesCircle;
}
