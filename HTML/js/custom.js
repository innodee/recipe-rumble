	
$(window).scroll(function () {
    var window_top = $(window).scrollTop() + 1;
    if (window_top > 100) {
      $('.menu-items-wrapper').addClass('menu-fixed animated fadeInDown');
    } else {
      $('.menu-items-wrapper').removeClass('menu-fixed animated fadeInDown');
    }
  });

    
    

    
    
    // Preloader 
    jQuery(window).on('load', function() {
        jQuery("#status").fadeOut();
        jQuery("#preloader").delay(450).fadeOut("slow");
    });
    
    
    
    // ===== Scroll to Top ==== //
    $(window).scroll(function() {
        if ($(this).scrollTop() >= 100) {
            $('#return-to-top').fadeIn(200);
        } else {
            $('#return-to-top').fadeOut(200);
        }
    });
    $('#return-to-top').click(function() {
        $('body,html').animate({
            scrollTop: 0
        }, 500);
    });	

   
		// responsive sab menu
		(function ($) {
            $(document).ready(function () {

                $('#cssmenu li.active').addClass('open').children('ul').show();
                $('#cssmenu li.has-sub>a').on('click', function () {
                    $(this).removeAttr('href');
                    var element = $(this).parent('li');
                    if (element.hasClass('open')) {
                        element.removeClass('open');
                        element.find('li').removeClass('open');
                        element.find('ul').slideUp(200);
                    }
                    else {
                        element.addClass('open');
                        element.children('ul').slideDown(200);
                        element.siblings('li').children('ul').slideUp(200);
                        element.siblings('li').removeClass('open');
                        element.siblings('li').find('li').removeClass('open');
                        element.siblings('li').find('ul').slideUp(200);
                    }
                });

            });
        })(jQuery);
// menu fixed

  
// toggle cross btn js
$(".toggle-main-wrapper , #toggle_close").on("click", function () {
    $("#sidebar").toggleClass("open")
});

$('.testimonial-slider .owl-carousel').owlCarousel({
  loop:true,
  margin:20,
  nav:true,
  dots: false,
  autoplay: true,
  navText: ['<img src="images/left-arrow.png">', '<img src="images/right-arrow.png">'],
  smartSpeed: 1200,
  responsive:{
      0:{
          items:1
      },
      600:{
          items:1
      },
      911:{
          items:1
      },
      1300:{
          items:1
      }
      
  }
})

$('.partner-slider .owl-carousel').owlCarousel({
    loop:true,
    margin:10,
    nav:true,
    dots: false,
    autoplay: true,
    smartSpeed: 1200,
    responsive:{
        0:{
            items:1
        },
        600:{
            items:3
        },
        991:{
            items:4
        },
        1199:{
            items:5
        },
        1300:{
            items:6
        }
        
    }
  })

  $('.product-slider .owl-carousel').owlCarousel({
    loop:true,
    margin:10,
    nav:true,
    dots: false,
    autoplay: true,
    navText: ['<img src="images/left.png">', '<img src="images/right.png">'],
    smartSpeed: 1200,
    responsive:{
        0:{
            items:1
        },
        600:{
            items:1
        },
        991:{
            items:1
        },
        1199:{
            items:1
        },
        1300:{
            items:1
        }
        
    }
  })

// counter js


		
 //**----- portfolio wrapper js -------**//
 
 function protfolioIsotope(){
    if ( $('.protfolio_area, .portfolio_grid').length ){ 
        // Activate isotope in container
        $(".protfoli_inner, .portfoli_inner").imagesLoaded( function() {
            $(".protfoli_inner, .portfoli_inner").isotope({
                layoutMode: 'masonry',  
            }); 
        });  
        
        // Add isotope click function 
        $(".protfoli_filter li").on('click',function(){
            $(".protfoli_filter li").removeClass("active");
            $(this).addClass("active"); 
            var selector = $(this).attr("data-filter");
            $(".protfoli_inner, .portfoli_inner").isotope({
                filter: selector,
                animationOptions: {
                    duration: 450,
                    easing: "linear",
                    queue: false,
                }
            });
            return false;
        });  
    };
}; 
protfolioIsotope (); 



//*------ zoom popup js code ------*//

    //          $('.zoom_popup').magnificPopup({
    //     delegate: 'a',
    //     type: 'image',
    //     tLoading: 'Loading image #%curr%...',
    //     mainClass: 'mfp-img-mobile',
    //     gallery: {
    //         enabled: true,
    //         navigateByImgClick: true,
    //         preload: [0, 1]
    //     },
    //     image: {
    //         tError: '<a href="%url%">The image #%curr%</a> could not be loaded.',
    //         titleSrc: function(item) {
    //             return item.el.attr('title') + '<small></small>';
    //         }
    //     }
    // });


    // search box


    

