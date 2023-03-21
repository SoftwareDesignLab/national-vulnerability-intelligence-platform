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
