/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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
