import { Injectable } from '@angular/core';
import { Observable, ReplaySubject } from 'rxjs';
import { ApiService } from '../Api/api-service.service';

export interface SingleDatum {
  name: string;
  value: number;
}

export enum ChartType {
  AddedUpdated = 0,
  NotInNVD = 1,
  TimeGap = 2,
}

@Injectable({
  providedIn: 'root'
})
export class ChartsService {
  chartData: Observable<SingleDatum[][]>;
  constructor(api: ApiService) {
    let temp: ReplaySubject<SingleDatum[][]> = new ReplaySubject(1);
    api.countGraphs((res: any) => {
      const data = res.map.mainPageCounts.map
      const { CvesAdded, CvesUpdated, avgTimeGapMitre, avgTimeGapNvd, not_in_mitre_count, not_in_nvd_count, run_date_times } = data;

      const dates = run_date_times.split(";").map((d: string) => new Date(d));

      const addedOrUpdatedSeries = this.makeAddedOrUpdatedSeries(
        CvesAdded.split(";").map((d: string) => parseInt(d)),
        CvesUpdated.split(";").map((d: string) => parseInt(d)),
        dates
      )

      const notInNvdSeries = this.makeNotInNVDSeries(
        not_in_nvd_count.split(";").map((d: string) => parseInt(d)),
        dates
      )

      const avgTimeGapNvdSeries = this.makeAverageGapTimeSeries(
        avgTimeGapNvd.split(";").map((d: string) => parseInt(d)),
        dates
      )

      temp.next([addedOrUpdatedSeries, notInNvdSeries, avgTimeGapNvdSeries]);
    })
    this.chartData = temp.asObservable()
  }

  private makeAddedOrUpdatedSeries(cveAdded: number[], cveUpdated: number[], dates: Date[]) {
    return dates.map((dateTime: Date, index: number) => ({ name: this.formatDateForColumnName(dateTime), value: cveAdded[index] + cveUpdated[index] })).reverse();
  }

  private makeNotInNVDSeries(notInNvdCount: number[], dates: Date[]) {
    return dates.map((dateTime: Date, index: number) => ({ name: this.formatDateForColumnName(dateTime), value: notInNvdCount[index] })).reverse()
  }

  private makeAverageGapTimeSeries(avgTimeGapNvd: number[], dates: Date[]) {
    return dates.map((dateTime: Date, index: number) => ({ name: this.formatDateForColumnName(dateTime), value: avgTimeGapNvd[index] })).reverse()
  }

  private formatDateForColumnName(date: Date) {
    return date.toLocaleDateString("en-US", {
      month: "numeric",
      day: "numeric",
    })
  }

  getData(): Observable<SingleDatum[][]> {
    return this.chartData;
  }
}
