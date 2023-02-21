import { Component, Input } from '@angular/core';
import { GoogleChartComponent } from './google-chart.component';
/** Gauge component for Vulnerability page */
@Component({
  selector: 'cvss-gauge',
  template: `
    <div
      class="vuln-characteristics-graph-container"
      id="cvssGauge"
      style="height: 130px; width: 100%"
    ></div>
  `,
})
export class GoogleGaugeComponent extends GoogleChartComponent {
  /** Google chart variables */
  private options: any;
  private data: any;
  private chart: any;
  @Input('cvssScore') cvssScore: any

  /** child drawgraph class that inits graph data, options, and then draws on page */
  override drawGraph() {
    this.data = this.createDataTable([
        ['Label', 'Value'],
        ['Base', 0],
        ['Impact', 0],
      ]);

      if (this.cvssScore.baseSeverity == "CRITICAL") {
        this.data.setValue(0, 1, 9.0);
      }
      else if (this.cvssScore.baseSeverity == "HIGH") { 
        this.data.setValue(0, 1, 7.0);
      }
      else if (this.cvssScore.baseSeverity == "MEDIUM") { 
        this.data.setValue(0, 1, 5.0);
      }
      else if (this.cvssScore.baseSeverity == "LOW") { 
        this.data.setValue(0, 1, 3.0);
      }
      if (this.cvssScore != undefined && this.cvssScore != null) {
        this.data.setValue(1, 1, parseFloat(this.cvssScore.impactScore));
      }

    this.options = {
        width: 800, height: 225,
        redFrom: 6.9, redTo: 10,
        yellowFrom: 5.5, yellowTo: 7.4,
        greenFrom:0, greenTo: 6.5,
        minorTicks: 6, max: 10,
      };

    this.chart = this.createGauge(
      document.getElementById('cvssGauge')
    );
    this.chart.draw(this.data, this.options);
  }
}
