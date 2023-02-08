import { Component, EventEmitter, Input, OnChanges, SimpleChanges, Output } from '@angular/core';
import { faAngleLeft, faAngleDown } from '@fortawesome/free-solid-svg-icons';
import { FuncsService } from 'src/app/services/Funcs/funcs.service';
/** Search dropdown component for VDO categories */
@Component({
  selector: 'search-dropdown',
  templateUrl: './search-dropdown.component.html',
  styleUrls: ['./search-dropdown.component.css']
})
export class SearchDropdownComponent {
  /** Font Awesome Icons */
  faAngleLeft = faAngleLeft;
  faAngleDown = faAngleDown;

  /** for dropped down component, rotate our arrow icon downward (-90 degrees) */
  rotationAmount = 0;

  /** hold state for which checkboxes are marked on the form */
  checkedLabels: Array<string> = [];

  @Input('label') label: string;
  @Input('entityLabels') entityLabels: Array<string>;
  @Output() selected = new EventEmitter<{selected: Array<string>}>

  /**
   * search dropdown constructor
   * @param funcs access globally defined functions instance
   */
  constructor(private funcs: FuncsService) {
    this.label = "";
    this.entityLabels = [];
  }

  /** update labels when we receive searchData from servlet */
  ngOnChanges(changes: SimpleChanges) {
    this.label = changes['label'].currentValue;
    this.entityLabels = changes['entityLabels'].currentValue;
  }

  //TODO: can probably make this more intuitive - current copy from old UI
  toggleContent($event: any) {
    // If the triggering element is a form checkbox, do not toggle.
		if ($event.srcElement.classList.contains("nvip-form-dropdown-checkbox")){
			return;
		}
		
		var formDropdown = this.funcs.getAncestor($event.srcElement as HTMLElement, "nvip-form-dropdown-field");
		var formContent = this.funcs.getSiblingByClassName(formDropdown as HTMLElement, "nvip-form-dropdown-content");
    var caretIcon = formDropdown!.getElementsByClassName("nvip-form-dropdown-caret")[0];
		
		if(formContent!.style.display == 'flex'){
      this.rotationAmount = 0;
			formDropdown!.classList.remove('dropdown-opened');
			formContent!.style.display = 'none';
      caretIcon.classList.add("fa-angle-left");
      caretIcon.classList.remove("fa-angle-down");
		}
		else{
      this.rotationAmount = -90;
			formDropdown!.classList.add('dropdown-opened');
			formContent!.style.display = 'flex';
			caretIcon.classList.remove("fa-angle-left");
	    caretIcon.classList.add("fa-angle-down");
		}
  }

  onChange(event: any, label: any) {
    // checkbox checked
    if (event.target.checked) {
      this.checkedLabels.push(label);
    }
    // checkbox unchecked
    else {
      const i = this.checkedLabels.indexOf(label, 0);
      this.checkedLabels.splice(i, 1);
    }
    this.selected.emit({selected: this.checkedLabels});
  }
}
