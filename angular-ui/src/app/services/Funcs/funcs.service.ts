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
  * modifies CSS to add login failure message
  */
  incorrectLogin(){
    var incorrectMessage = document.getElementById('loginMessage') as HTMLDivElement;

    incorrectMessage.style.display = 'block';
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
