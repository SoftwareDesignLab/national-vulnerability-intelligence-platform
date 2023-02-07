export interface SearchCriteria {
  keyword: string;
  cve_id: string;
  limitCount: number;
  startDate: string;
  endDate: string;
  product: string;
  vdoLabels: Array<string>;
  cvssScores: Array<string>;
}
