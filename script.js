document.addEventListener('DOMContentLoaded', () => {

    const sectionsToFade = document.querySelectorAll('.fade-in-section');

    if (!sectionsToFade.length) {
        return;
    }

    const observer = new IntersectionObserver((entries, observer) => {
        
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                
                entry.target.classList.add('is-visible');
                
                observer.unobserve(entry.target);
            }
        });
    }, {
        root: null,
        threshold: 0.1
    });

    sectionsToFade.forEach(section => {
        observer.observe(section);
    });

});
