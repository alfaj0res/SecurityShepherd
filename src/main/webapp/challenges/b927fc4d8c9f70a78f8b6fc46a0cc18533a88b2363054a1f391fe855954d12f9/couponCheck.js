// Coupons are checked on the server. No coupon data or keys are sent to the browser
function checkCoupon(couponCode) {
	var ajaxCall = $.ajax({
		type: "POST",
		url: "b927fc4d8c9f70a78f8b6fc46a0cc18533a88b2363054a1f391fe855954d12f9.jsp",
		data: {
			checkCouponCode: couponCode
		},
		async: false
	});
	return ajaxCall.status == 200 && ajaxCall.responseText == "true";
}
