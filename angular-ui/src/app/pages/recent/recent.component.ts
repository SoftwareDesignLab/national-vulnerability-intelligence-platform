import { Component, OnInit } from '@angular/core';
import { faSpinner } from '@fortawesome/free-solid-svg-icons';
import { VulnService } from 'src/app/services/vuln/vuln.service';
/** Recent Vulnerabilities page */

/** Key-value store object of recent date and dropdowns to display on that date */
export interface VulnMap {
  date: string;
  cve_list: Array<any>;
}

/** Array of date-list vuln pages to navigate through */
export interface VulnMaps extends Array<VulnMap> {}

@Component({
  selector: 'nvip-recent',
  templateUrl: './recent.component.html',
  styleUrls: ['./recent.component.css'],
})
export class RecentComponent implements OnInit {
  /** FontAwesome Icon */
  faSpinner = faSpinner;

  /** Variables to hold state of which date we are on and
   * how much we have increased/decreased a certain pages limit,
   * and what vulns are on each page
   */
  dailyVulnLimit: Array<number> = [];
  vulnLimitIncr: number = 5;
  dailyVulnIndex: number = 0;
  dailyVulns: VulnMaps = [];
  currentSelected: number = -1;

  /**
   * constructor
   * @param vulnService to access vulnerabilityServlet endpoints 
   */
  constructor(private vulnService: VulnService) {}

  /** call recent vulnerabilites on page init */
  ngOnInit() {
    this.vulnService.onRecentInit().subscribe((res: any) =>
      Object.keys(res).forEach((key) => {
        this.dailyVulns.push({
          date: this.formatDate(res[key].date),
          cve_list: res[key].list,
        });
        this.dailyVulnLimit.push(this.vulnLimitIncr);
      })
    );
  }

  /** format title date */
  formatDate(dateString: string) {
    const timeZone = 'T00:00:00.000-08:00';
    const date = new Date(dateString + timeZone);
    return date.toDateString();
  }

  /** helper to determine whether a show more or show less button is disabled */
  isDisabled(isMore: boolean, panelIndex: number, vulnMap: VulnMap) {
    if (isMore)
      return this.dailyVulnLimit[panelIndex] >= vulnMap.cve_list.length;
    else return this.dailyVulnLimit[panelIndex] <= this.vulnLimitIncr;
  }

  /** helper for arrows back and forth between recent dates */
  incrementDailyVulnDay(incr: number) {
    if ( (this.dailyVulnIndex + incr < 0) || (this.dailyVulnIndex + incr >= this.dailyVulns.length) ) {
      return;
    }
    this.dailyVulnIndex = this.dailyVulnIndex += incr;
  }

  /** trigger more recent vulns under that day to show */
  showMore(panelIndex: number) {
    this.dailyVulnLimit[panelIndex] =
      this.dailyVulnLimit[panelIndex] + this.vulnLimitIncr;
  }

  /** trigger removal of last 5 vulns showing under that day */
  showLess(panelIndex: number) {
    const newLimit: number = this.dailyVulnLimit[panelIndex] - this.vulnLimitIncr;
    if (newLimit < this.vulnLimitIncr) {
      this.dailyVulnLimit[panelIndex] = this.vulnLimitIncr;
    } else {
      this.dailyVulnLimit[panelIndex] = newLimit;
    }
  }

  /** helper function for emitting collapsing of other dropdowns when a new one is selected */
  setCurrentSelected(event: any) {
    this.currentSelected = event['index'];
  }
}
