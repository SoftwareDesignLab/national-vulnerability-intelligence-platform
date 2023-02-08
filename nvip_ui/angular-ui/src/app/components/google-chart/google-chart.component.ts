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