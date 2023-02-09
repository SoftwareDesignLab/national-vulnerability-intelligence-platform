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
  @Output() loaded = new EventEmitter<{loaded: boolean}>;

  mySubscription: Subscription | undefined;

  data: SingleDatum[] = [];
  chartsService: ChartsService;
  options = {
    roundEdges: false,
    showXAxis: true,
    showYAxis: true,
    gradient: false,
    showLegend: false,
    showXAxisLabel: false,
    showYAxisLabel: false,
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
    this.chartsService.getData().subscribe((data) => this.data = data[this.chartType])
    this.loaded.emit({ loaded: true })
  }

  onSelect(data: unknown): void {
  }

  onActivate(data: unknown): void {
  }

  onDeactivate(data: unknown): void {
  }
}
