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
import { Component, OnInit} from '@angular/core';
/** Google Chart boilerplate to connect gauges */

/** access static google instance */
declare var google:any;

@Component({
  selector: 'google-chart',
  template: ''
})
export class GoogleChartComponent implements OnInit {
  /** Ensure we have google instances loaded up */
  private static googleLoaded:any;

  /** get the google charts instance */
  getGoogle() {
      return google;
  }

  /** load in Gauge and other charts on init */
  ngOnInit() {
    if(!GoogleChartComponent.googleLoaded) {
      GoogleChartComponent.googleLoaded = true;
      google.charts.load('current',  {packages: ['corechart', 'bar', 'gauge']});
    }
    google.charts.setOnLoadCallback(() => this.drawGraph());
  }

  /** parent class to be inherited by gauge */
  drawGraph(){
      // console.log("DrawGraph base class!!!! ");
  }

  /** instantiate Gauge components inside our vulnerability screen */
  createGauge(element:any):any {
      return new google.visualization.Gauge(element);
  }

  /** data passed to gauge helper function */
  createDataTable(array:any[]):any {
      return google.visualization.arrayToDataTable(array);
  }
}