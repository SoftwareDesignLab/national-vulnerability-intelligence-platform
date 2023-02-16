app.controller('LoginController', ['$scope', '$rootScope', '$location', 'AUTH_EVENTS', 'AuthService', '$cookieStore', 
	function ($scope, $rootScope, $location, AUTH_EVENTS, AuthService, $cookieStore) {
	// TODO: Clear credentials after login successful OR remove need for scope object when passing data
	$scope.credentials = {
			username: '',
			password: ''
	};
	
	$scope.login = function (credentials) {
		AuthService.login($scope.credentials).then(function (user) {
			$rootScope.$broadcast(AUTH_EVENTS.loginSuccess);
			if(AuthService.isAuthenticated()){
				//$scope.setCurrentUser(user);
				$location.path("");
			}
		  }, 
		  function () {
			  $rootScope.$broadcast(AUTH_EVENTS.loginFailed);
		});
	};
	
	$scope.isLoggedIn = function() {
  		return AuthService.isAuthenticated();
  	}
	
	//Redirects to Search page if logged in, otherwise, will display login panel
	$scope.goToSearch = function() {
		if ($scope.isLoggedIn()) {
			window.location.href = '#search/';
		} else {
			$scope.enableLoginMessage();
		}
	}
	
	//Redirects to Recent Vulnerabilities page (main.html) if logged in
	//Otherwise, will display login panel
	$scope.goToRecVulns = function() {
		if ($scope.isLoggedIn()) {
			window.location.href = '#';
		} else {
			$scope.enableLoginMessage();
		}
	}
	
	//Disaplys login panel with "Login Required Message"
	$scope.enableLoginMessage = function() {
		document.getElementById("loginPanel").style.display = "block";
		document.getElementById("nvipContent").style.filter = "blur(100px)"
		document.getElementById("loginMessage").style.display = "block";
		document.getElementById("loginMessage").innerText = "Please login to view and search for vulnerabilities";
		document.getElementById("loginForm").style.marginTop = "5.5em";
	}
	
	$scope.getUsername = function() {
		var user = $cookieStore.get('nvip_user');
		
		if (user != null){
			return user.username;
		}
		
		return null;
	}
	
	$scope.getFirstName = function() {
		var user = $cookieStore.get('nvip_user');
		
		if (user != null){
			return user.firstname;
		}
		
		return null;
	}
	
	$scope.logOut = function() {
		$cookieStore.remove('nvip_user');
		window.location.reload();
		return null;
	}
	
	$scope.getUserRole = function() {
		var user = $cookieStore.get('nvip_user');
		
		if (user != null){
			return user.role;
		}
		
		return null;
	}
	
}]);