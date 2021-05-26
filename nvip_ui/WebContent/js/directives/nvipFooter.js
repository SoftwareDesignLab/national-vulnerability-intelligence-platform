/**
 * 
 */
app.directive('nvipFooter', function() {
	 return {
		 link: function (scope, elem, attrs) {
			
		 },
		 restrict: "E",
		 scope: {
		 },
		 template: 
		 `<div class="nvip-footer col-12">
			<p>
				Performer is looking for feedback on its stand-up software vulnerabilities platform and methodology for detecting and reporting software vulnerabilities for software assurance community by establishing a website for obtaining feedback to assist with their research. S&T is funding this research through contract 70RSAT19CB0000020
			</p>
			<div class="nvip-footer-contents">
				<a href="#about/">About NVIP</a><a href="#privacy/">Privacy Policy</a><a href = "mailto: admin@cve.live">Contact Us</a>
			</div>
			<div class="nvip-footer-social-media">
				<p>Follow us <a href="https://twitter.com/LiveCve" target="_blank">@Twitter</a> @LinkedIn @Facebook</p>
			</div>
		</div>`
	 };
});