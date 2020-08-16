var data = CreateList()
var reviews = CreateReview()
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
        for (product in data){
            if (data[product][parseInt(1)] == item){
                $("#item-details").html("<span>" + data[product][parseInt(1)] + "</span><br><span>" + data[product][parseInt(2)] + "</span><br><span>Price: $" + data[product][parseInt(3)].toFixed(2) + "</span>");
                $("#item-desc").text(data[product][parseInt(4)]);
                if (data[product][parseInt(4)] != null){
                    $("#item-image").attr("src", "../static/img/" + data[product][parseInt(5)]);
                }
                else{
                    $("#item-image").attr("src", "../static/img/None.png");
                };
                for (entry in reviews){
                    if (reviews[entry][parseInt(0)] == data[product][parseInt(0)]){
                        $(".reviews").text($(".reviews").text() + reviews[entry][parseInt(1)] + ": " + reviews[entry][parseInt(2)] + "\n")
                    };
                };
            };
        };
    });

    // hide overlay when overlay is clicked
    $(".overlay").on("click", function(){
        if (!($(".overlay-item").data("clicked"))){
            $(".overlay").hide();
            $("#item-details").text("");
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

    $("#form-review").attr("action", "/login");
    $(".add-cart").attr("action", "/login");
})