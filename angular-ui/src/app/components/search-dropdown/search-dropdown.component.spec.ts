import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SearchDropdownComponent } from './search-dropdown.component';

describe('SearchDropdownComponent', () => {
  let component: SearchDropdownComponent;
  let fixture: ComponentFixture<SearchDropdownComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ SearchDropdownComponent ]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SearchDropdownComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
