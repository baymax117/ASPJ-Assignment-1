var data = createList();
var reviews = createReview();
$(document).ready(function(){
    $(".item-container").on("click", function(){
        $("#form-review").attr("action", "/login");
        $(".add-cart").attr("action", "/login");
        });
});