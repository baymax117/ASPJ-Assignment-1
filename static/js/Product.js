var data = createList();
var reviews = createReview();
$(document).ready(function(){
    // "pop up" item when mouse enters the box
    $(".item-container").on("mouseenter", function(){
        $(this).addClass("item-container-active");
    });

    // revert item when mouse leaves the box
    $(".item-container").on("mouseleave", function(){
        $(this).removeClass("item-container-active");
    });

    // show overlay when item is clicked
    $(".item-container").on("click", function(){
        var item = $(this).attr("id");
        $(".overlay").show();
        for (var product in data){
            if (data[parseInt(product, 10)][parseInt(1, 10)] === item){
                $("#item-details").html("<span>" + data[parseInt(product, 10)][parseInt(1, 10)] + "</span><br><span>" + data[parseInt(product, 10)][parseInt(2, 10)] + "</span><br><span>Price: $" + data[parseInt(product, 10)][parseInt(3, 10)].toFixed(2) + "</span>");
                $("#item-desc").text(data[parseInt(product, 10)][parseInt(4, 10)]);
                $("#form-review").attr("action", "/api/Reviews/add/" + data[parseInt(product, 10)][parseInt(0, 10)]);
                $(".add-cart").attr("action", "/api/Cart/add_cart/" + data[parseInt(product, 10)][parseInt(0, 10)]);
                if (data[parseInt(product, 10)][parseInt(4, 10)] !== null){
                    $("#item-image").attr("src", "../static/img/" + data[parseInt(product, 10)][parseInt(5, 10)]);
                }
                else{
                    $("#item-image").attr("src", "../static/img/None.png");
                }
                for (var entry in reviews){
                    if (reviews[parseInt(entry, 10)][parseInt(0, 10)] === data[parseInt(product, 10)][parseInt(0, 10)]){
                        $(".reviews").text($(".reviews").text() + reviews[parseInt(entry, 10)][parseInt(1, 10)] + ": " + reviews[parseInt(entry, 10)][parseInt(2, 10)] + "\n");
                    }
                }
            }
        }
    });

    // hide overlay when overlay is clicked
    $(".overlay").on("click", function(){
        if (!($(".overlay-item").data("clicked"))){
            $(".overlay").hide();
            $("#item-details").text("");
            $("#form-review").attr("action", "");
            $(".add-cart").attr("action", "");
            $("#item-image").attr("src", "../static/img/None.png");
            $(".overlay-item").data("clicked", false);
            $(".reviews").html("");
            }
        else{
            $(".overlay-item").data("clicked", false);
        }
    });

    $(".overlay-item").on("click", function(){
        $(this).data("clicked", true);
    });


});