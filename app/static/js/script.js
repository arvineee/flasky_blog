document.addEventListener("DOMContentLoaded", () => {
    const videos = document.querySelectorAll(".custom-video");

    videos.forEach((video, index) => {
        const videoWrapper = video.closest(".video-wrapper");
        const playOverlay = videoWrapper.querySelector(".play-overlay");
        const bigPlayButton = videoWrapper.querySelector(".big-play-button");

        // Pause all other videos when a video starts
        const pauseAllVideos = () => {
            videos.forEach((vid) => {
                if (vid !== video) {
                    vid.pause();
                    vid.closest(".video-wrapper").querySelector(".play-overlay").style.display = "flex";
                }
            });
        };

        // Play video on button click
        bigPlayButton.addEventListener("click", () => {
            video.play();
            playOverlay.style.display = "none";
        });

        // Show overlay when paused
        video.addEventListener("pause", () => {
            playOverlay.style.display = "flex";
        });

        // Hide overlay when playing
        video.addEventListener("play", () => {
            pauseAllVideos();
            playOverlay.style.display = "none";
        });

        // Auto-scroll and play next video
        video.addEventListener("ended", () => {
            const nextVideo = videos[index + 1];
            if (nextVideo) {
                nextVideo.scrollIntoView({ behavior: "smooth" });
                setTimeout(() => nextVideo.play(), 1000);
            }
        });

        // Pause video when out of viewport
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) {
                    video.pause();
                }
            });
        }, { threshold: 0.5 });

        observer.observe(video);
    });
});
