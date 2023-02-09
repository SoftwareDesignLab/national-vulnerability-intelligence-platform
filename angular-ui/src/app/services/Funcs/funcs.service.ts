import { Injectable } from '@angular/core';
/** Function service */
@Injectable({
  providedIn: 'root'
})
export class FuncsService {

  /**
   * modifies CSS to hide login panel
   */
  closeLogin() {
    var loginPanel = document.getElementById('loginPanel') as HTMLDivElement;
    var nvipContent = document.getElementById('nvipContent') as HTMLDivElement;
    var loginForm = document.getElementById('loginForm') as HTMLDivElement;

    loginPanel.style.display = 'none';
    loginPanel.style.opacity = '0';
    loginForm.style.marginTop = '0';
    nvipContent.style.filter = 'blur(0px)';
  }

  /**
   * legacy angularjs function - return a page element to be updated later on
   * @param element parent element to search
   * @param className classname of given element
   * @returns the element if it is found on the document, null otherwise
   */
  getAncestor(element: HTMLElement, className: string) {
	
    if (element == null) {
      return null;
    }
    
    // If the given element has the desired class, return it instead of looking for
    // an earlier class
    if(element.classList.contains(className)){
      return element;
    }
    
    var parent = element.parentElement; 
    
    while(parent != null){
      if (parent.classList.contains(className)) {
        return parent;
      }
      parent = parent.parentElement;
    }
    
    return null;
  }
  
  /**
   * legacy angularjs function - get sibling element found on the same page
   * @param element element to look for sibling in
   * @param className classname to look for
   * @returns the sibling if found on the document, null otherwise
   */
  getSiblingByClassName(element: HTMLElement, className: string) {
    if (element == null){
      return null;
    }
    
    var sibling = element.nextSibling as HTMLElement;
    
    while(sibling){
      if(sibling.nodeType === 1 && sibling != element){
        if (sibling.classList.contains(className)){
          return sibling;
        }
      }
      
      sibling = sibling.nextSibling as HTMLElement;
    }
    
    return null;
  }

}
