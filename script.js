(function (root) {

    var screen1 = document.getElementById('screen1'),
        screen2 = document.getElementById('screen2'),
        filePass = document.getElementById('filePass'),
        fileName = document.getElementById('fileName'),
        status = document.getElementById('status'),
        hlabel = document.getElementById('hlabel'),
        errh = document.getElementById('errh'),
        box = document.getElementById('box'),
        dropzone = document.getElementById('dropzone'),
        progressThumb = document.getElementById('progressThumb'),
        fileBox = document.getElementById('fileBox'),
        lastDropItem = null,
        processed = 0,
        fileToProtect = null;

    var reset = function () {
        var clone = fileBox.cloneNode(false);
        fileBox.parentNode.replaceChild(clone, fileBox);
        fileBox = document.getElementById('fileBox');
        fileBox.addEventListener('change', fileOnChange);

        fileToProtect = null;
        filePass.value = '';
        fileName.value = '';
        hlabel.removeAttribute('class');
        filePass.setAttribute('class', 'text');
        status.style.display = 'none';
        screen2.style.display = 'none';
        screen1.style.display = 'block';
        errh.style.display = 'none';
    };

    var onDragOver = function (e) {
        e.preventDefault();
    };

    var onDragEnter = function (e) {
        lastDropItem = e.target;
        dropzone.style.display = 'block';
    };

    var onDragLeave = function (e) {
        if (lastDropItem === e.target) {
            dropzone.style.display = 'none';
        }
    };

    var fileOnChange = function () {
        var files = fileBox.files;
        if (!files.length) {
            return;
        }
        setFile(fileBox.files[0]);
    };

    var fileOnDrop = function (e) {
        dropzone.style.display = 'none';
        e.stopPropagation();
        e.preventDefault();
        var files = e.dataTransfer.files;
        if (!files.length) {
            return;
        }
        setFile(files[0]);
    };

    var setFile = function (file) {
        fileToProtect = file;
        screen1.style.display = 'none';
        screen2.style.display = 'block';
        hlabel.innerHTML = 'Protect your files';
        fileName.value = fileToProtect.name;
        fileName.setAttribute('title', fileToProtect.name);
    };

    var success = function () {
        reset();
        processed = 0;
        hlabel.innerHTML = 'Done. Protect more files';
        errh.style.display = 'none';
        progressThumb.style.width = 0;
    };

    var error = function (code) {
        var err = '';
        switch (code) {
            case 1:
                err = 'Incorrect password or file is corrupt.';
                break;
            case 2:
                err = 'Password cannot be blank.';
                break;
            case 3:
                err = 'Password must be at least 4 characters long.';
                break;
            case 4:
                err = 'Password too long. Max: 32 characters.';
                break;
        }
        processed = 0;
        progressThumb.style.width = 0;
        filePass.value = '';
        screen2.style.display = 'block';
        status.style.display = 'none';
        errh.style.display = 'block';
        hlabel.innerHTML = 'Error!';
        errh.innerHTML = err;
        filePass.setAttribute('class', 'text haserror');
        hlabel.setAttribute('class', 'haserrorh');
    };

    var handleProgress = function (procAmount, total) {
        processed += procAmount;
        var wdt = parseInt(processed / total * 100);

        progressThumb.style.width = wdt.toString() + '%';
    };

    var validatePass = function () {
        if (!filePass.value.length) {
            error(2);
            return false;
        }
        if (filePass.value.length < 4) {
            error(3);
            return false;
        }
        if (filePass.value.length > 32) {
            error(4);
            return false;
        }
        return true;
    };

    var smfInst = new SecureMyFiles(success, error, handleProgress, true);
    fileBox.addEventListener('change', fileOnChange);
    dropzone.addEventListener('dragover', onDragOver);
    window.addEventListener('dragenter', onDragEnter);
    window.addEventListener('dragleave', onDragLeave);
    dropzone.addEventListener('drop', fileOnDrop);

    window.encrypt = function () {
        if (!validatePass()) {
            return;
        }
        hlabel.removeAttribute('class');
        screen2.style.display = 'none';
        status.style.display = 'block';
        hlabel.innerHTML = "Processing...";
        smfInst.encryptFile(fileToProtect, filePass.value);
    };

    window.decrypt = function () {
        if (!validatePass()) {
            return;
        }
        hlabel.removeAttribute('class');
        screen2.style.display = 'none';
        status.style.display = 'block';
        hlabel.innerHTML = "Processing...";
        smfInst.decryptFile(fileToProtect, filePass.value);
    };

    window.goBack = function () {
        reset();
        hlabel.innerHTML = "Add some files to begin";
    };

})(this);