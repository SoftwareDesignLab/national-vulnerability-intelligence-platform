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
import { Component, Input, OnChanges, SimpleChanges, Output, EventEmitter } from '@angular/core';
import { faAngleDown } from '@fortawesome/free-solid-svg-icons';
import { Vulnerability, VDO } from 'src/app/models/vulnerability.model';
/** Vulnerability dropdown component - holds CVE state in dropdown on review and search pages */
@Component({
  selector: 'daily-vuln-dropdown',
  templateUrl: './daily-vuln-dropdown.component.html',
  styleUrls: ['./daily-vuln-dropdown.component.css'],
})
export class DailyVulnDropdownComponent implements OnChanges {
  /** FontAwesome Icons */
  faAngleDown = faAngleDown;
  /** Styling variables */
  confidenceThreshold = 0.3;
  active: boolean = false;
  activeDescColor: string = 'black';
  inactiveDescColor: string = 'rgba(64, 64, 64, 0.7)';
  showMoreDescription: boolean = false;
  /** Noun groups constants */
  VDO_NOUN_GROUPS = {
    all: '*',
    ATTACK_THEATER: 'AttackTheater',
    CONTEXT: 'Context',
    IMPACT_METHOD: 'ImpactMethod',
    LOGICAL_IMPACT: 'LogicalImpact',
    MITIGATION: 'Mitigation',
  };

  @Input('vuln') vuln: Vulnerability;
  @Input('index') index: number;
  @Input('currentToggle') currentToggle: number;
  @Output() selected = new EventEmitter<{ index: number }>

  constructor() {
    this.vuln = {} as Vulnerability;
    this.index = 0;
    this.currentToggle = -1;
  }

  /**
   * perform state updates on input changes
   * @param changes interface object holding current and previous values in change
   */
  ngOnChanges(changes: SimpleChanges) {
    if (changes['vuln']) this.vuln = changes['vuln'].currentValue;
    if (changes['index']) this.index = changes['index']?.currentValue;
    if (this.index !== changes['currentToggle'].currentValue) this.active = false;
  }

  /**
   * helper function for determining red or green ring around mitigation
   * @param nounGroup noun group category
   * @returns the vdo labels under that VDO category
   */
  getVdoLabelsByNounGroup(nounGroup: string) {
    var vdoLabels: Array<string> = [];
    this.vuln.vdoList.forEach((vdo: VDO) => {
      if (vdo.vdoNounGroup == nounGroup) {
        vdoLabels.push(vdo.vdoLabel);
      }
    });
    if (vdoLabels.length == 0) return 'Unknown';
    return vdoLabels;
  }

  /**
   * determines red or green ring around mitigation icon
   * @returns true (green) or false (red)
   */
  hasMitigation() {
    var vdoLabels = this.getVdoLabelsByNounGroup(
      this.VDO_NOUN_GROUPS.MITIGATION
    );
    if (vdoLabels == 'Unknown') return false;
    else return true;
  }

  /**
   * determines red or green ring around fixed icon
   * @returns true (green) or false (red)
   */
  isFixed() {
    if (this.vuln.fixDate !== "N/A")
      return true;
    return false;
  }

  /** get VDO list based on a given noun group constant */
  getVdoList(nounGroup: string) {
    var newVdoList: Array<VDO> = [];
    this.vuln.vdoList.forEach((vdo: VDO, i: number) => {
      if (vdo.vdoNounGroup == nounGroup) {
        if (vdo.vdoConfidence >= this.confidenceThreshold) {
          newVdoList.push(vdo);
        }
      }
    });
    return newVdoList;
  }

  /**
   * sort our impact and method lists on dropdown
   * @param limitTo how many to show on dropdown
   * @param orderBy means of sorting, whether by confidence or another metric
   * @param nounGroup vdo group to be sorted
   * @returns sorted list of VDO to be displayed in dropdown
   */
  sortBy(limitTo: number, orderBy: string, nounGroup: string): Array<VDO> {
    return this.getVdoList(nounGroup)
      .sort((a, b) =>
        a[orderBy as keyof VDO] > b[orderBy as keyof VDO]
          ? 1
          : a[orderBy as keyof VDO] == b[orderBy as keyof VDO]
            ? 0
            : -1
      )
      .slice(0, limitTo);
  }

  /** get label class based on vdo confidence metric */
  getLabelClass(vdo: VDO) {
    if (vdo.vdoConfidence >= 0.65) {
      return 'vuln-vdo-label vdo-high-confidence';
    } else if (vdo.vdoConfidence >= 0.3) {
      return 'vuln-vdo-label vdo-med-confidence';
    } else if (vdo.vdoConfidence > -1) {
      return 'vuln-vdo-label vdo-low-confidence';
    } else {
      return 'vuln-vdo-label';
    }
  }

  /** styling for whether a dropdown is active or not */
  getHeaderClass() {
    var c: string = this.active ? 'daily-vuln-active' : '';
    return c;
  }

  /** helper to return either shortened version of description of full description */
  getDescription() {
    if (this.showMoreDescription) return this.vuln.description
    else return this.vuln.description.slice(0, 997) + '...'
  }

  /** trigger styling updates and emit selected index to 
   * indicate to other dropdowns that they should collapse
   */
  selectDailyCve() {
    if (this.active) {
      // do inactive setting stuff
      this.active = false;
    }
    else {
      this.active = true;
      this.selected.emit({ index: this.index });
    }
  }

  /** toggle larger description under dropdown */
  vulnDescToggle($event: any) {
    this.showMoreDescription = !this.showMoreDescription;
  }
}
