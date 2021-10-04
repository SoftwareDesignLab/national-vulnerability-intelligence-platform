/**
 * 
 */
app.directive('nvipHeader', function() {
	
	 return {
		 link: function (scope, elem, attrs) {
			
		 },
		 restrict: "E",
		 scope: {
		 },
		 template: 
		 `<div class="nvip-header" ng-controller="LoginController as LoginCtrl">
		 	
			<div class="nvip-logo-container">
				<a href="#/login" class="nvip-logo">
					<img src="images/nvip-simple-logo.jpg" alt="NVIP">
				</a>
			</div>
			
			<div class="nvip-header-container">
				<div id="userView"  class="nvip-header-links" style="display:flex; width:100%">
					
					<div class="nvip-header-link">
						<a href="#about/">About NVIP</a>
					</div>
					
					<div class="nvip-header-link">
						<a ng-click="goToRecVulns()">Recent Vulnerabilities</a>
					</div>
					
					<div class="nvip-header-link">
						<a ng-click="goToSearch()">Search</a>
					</div>
					
					<div id="adminElement" class="nvip-header-link" style="display:none">
						<a href="#review/">Review</a>
					</div>
					
					<div id="userBlock" style="width:20%"></div>
					
					<div class="nvip-header-link" ng-hide="isLoggedIn()">
						<a onclick="openLogin()" ng-hide="isLoggedIn()">Login</button>						
					</div>
					
					<div class="nvip-header-user-icon-container" style="float:right; width: 20%" ng-hide="!isLoggedIn()">
						<a class="nvip-header-user-icon fa fa-sign-out" ng-hide="!isLoggedIn()" aria-hidden="true" ng-click="logOut()" href="#"></a>
						<p class="nvip-user-label" ng-hide="!isLoggedIn()">Welcome, {{getFirstName()}} </p>	
					</div>
					
				</div>
			</div>
			
		 </div>`
			 
	 };
});

function switchViewToAdmin(show, $timeout) { 
	
	$timeout(function () {
	    //DOM has finished rendering
		var userView = document.getElementById("userBlock");
		var adminView = document.getElementById("adminElement");
		
		if (userView == null || adminView == null) {
			console.log('No header');
			return;
		}
			
		if (show){ 
			adminView.style.display = "block";
			userView.style.display = "none";
		}
		else{
			userView.style.display = "block";
			adminView.style.display = "none";
		}
		
	}, 500);
}

//Opens Login Panel without Login message
function openLogin() {
	document.getElementById("loginPanel").style.display = "block";
	//document.getElementById("loginPanel").style.visibility = "visible";
	//document.getElementById("loginPanel").style.opacity = 1;
	document.getElementById("nvipContent").style.filter = "blur(100px)";
	document.getElementById("loginMessage").style.display = "none";
	document.getElementById("loginForm").style.marginTop = "4em";
}

function closeLogin() {
	document.getElementById("loginPanel").style.display = "none";
	//document.getElementById("loginPanel").style.opacity = 0;
	document.getElementById("loginForm").style.marginTop = "0";
	document.getElementById("nvipContent").style.filter = "blur(0px)"
}


