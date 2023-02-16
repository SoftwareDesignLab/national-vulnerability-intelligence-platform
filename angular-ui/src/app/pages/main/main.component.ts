import { Component } from '@angular/core';
import {
  faDatabase,
  faCubes,
  faStarHalfAlt,
  faSpinner,
} from '@fortawesome/free-solid-svg-icons';
/** Main landing page */
@Component({
  selector: 'nvip-main',
  templateUrl: './main.component.html',
  styleUrls: ['./main.component.css'],
})
export class MainComponent {
  /** FontAwesome Icons */
  faDatabase = faDatabase;
  faCubes = faCubes;
  faStarHalf = faStarHalfAlt;
  faSpinner = faSpinner;
  /** Persist loading icon until all of these are true */
  chartsLoaded = [false, false, false];

  /** Check if every chart has been initalized, if not, keep loading icon */
  isChartsLoaded() {
    return this.chartsLoaded.every((v) => v === true);
  }

  /** update chartLoaded array if a given chart is ready to go */
  isLoaded(eventData: { loaded: boolean }, chartNum: number) {
    this.chartsLoaded[chartNum] = eventData.loaded;
  }
}
