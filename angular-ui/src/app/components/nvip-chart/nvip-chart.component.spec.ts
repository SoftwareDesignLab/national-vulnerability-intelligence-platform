import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NvipChartComponent } from './nvip-chart.component';

describe('NvipChartComponent', () => {
  let component: NvipChartComponent;
  let fixture: ComponentFixture<NvipChartComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ NvipChartComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(NvipChartComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
