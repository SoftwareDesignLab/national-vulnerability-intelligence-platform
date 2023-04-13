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
import { Component, EventEmitter, Input, OnDestroy, OnInit, Output } from '@angular/core';
import { ScaleType } from '@swimlane/ngx-charts';
import { Subscription } from 'rxjs';
import { ChartsService, ChartType, SingleDatum } from 'src/app/services/Chart/charts.service';

@Component({
  selector: 'nvip-chart',
  templateUrl: './nvip-chart.component.html',
  styleUrls: ['./nvip-chart.component.css']
})
export class NvipChartComponent implements OnInit, OnDestroy {
  @Input() chartType!: ChartType;
  @Output() loaded = new EventEmitter<{ loaded: boolean }>;

  mySubscription: Subscription | undefined;

  data: { name: string, series: SingleDatum[] }[] = [{ name: "", series: [] }];
  chartsService: ChartsService;
  options = {
    roundEdges: false,
    showXAxis: true,
    showYAxis: true,
    gradient: false,
    showLegend: false,
    showXAxisLabel: false,
    showYAxisLabel: true,
    yAxisLabel: "Quantity"
  };

  colorScheme = {
    domain: ["#d9895d"],
    name: "",
    selectable: false,
    group: ScaleType.Linear
  }

  constructor(chartsService: ChartsService) {
    this.chartsService = chartsService;
  }
  ngOnDestroy(): void {
    this.mySubscription?.unsubscribe();
  }
  ngOnInit(): void {

    this.chartsService.getData().subscribe((data) => {
      console.log(data[this.chartType]);
      this.data = [{ name: this.chartType.toLocaleString(), series: data[this.chartType] }];
    })
    if (this.chartType == 2) {
      this.options.yAxisLabel = "Hours"
    }
    this.loaded.emit({ loaded: true })
  }

  onSelect(data: unknown): void {
  }

  onActivate(data: unknown): void {
  }

  onDeactivate(data: unknown): void {
  }
}
