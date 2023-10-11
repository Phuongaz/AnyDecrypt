function submitForm(event) {
    event.preventDefault();

    document.getElementById("loading").style.display = "block";

    const ip = document.getElementById("ip").value;
    const port = document.getElementById("port").value;

    fetch(`/decrypt?ip=${ip}&port=${port}`)
        .then(response => {
            if (response.ok) {
                return response.blob();
            } else {
                throw new Error('Decryption failed');
            }
        })
        .then(blob => {
            document.getElementById("loading").style.display = "none";

            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `${ip}.zip`;

            const fileSize = (blob.size / (1024 * 1024)).toFixed(2);
            const fileSizeText = `${fileSize} MB`;
            const sizeInfo = document.createElement("p");
            sizeInfo.innerText = `File size: ${fileSizeText}`;

            document.getElementById("btn-decrypt").style.display = "none";

            const downloadButton = document.getElementById("btn-download");
            downloadButton.style.display = "block";
            downloadButton.href = url;

            downloadButton.addEventListener("click", () => {
                a.click();
            });

            const container = document.getElementById("btn-download");
            container.appendChild(sizeInfo);
        })
        .catch(error => {
            console.error(error);
        });
}
