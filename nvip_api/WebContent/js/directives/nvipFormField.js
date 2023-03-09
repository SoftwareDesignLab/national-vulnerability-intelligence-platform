app.directive('nvipFormField', [function(VDO_NOUN_GROUPS) {
	 return {
		 link: function (scope, elem, attrs) {
			
		 },
		 restrict: "E",
		 scope: {
			labelFor: '@',
			model: '@',
			type:  '@'
		 },
		 template: 
			 `
			 	<div class="nvip-form-field">
						<label for=labelFor>Keyword</label>
						<input type=type ng-model="search.keyword" />
					</div>
	     `
	 };
}]);