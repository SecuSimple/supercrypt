(function (root) {
  //Code goes here

  //exposing the namespace
  if (typeof exports !== 'undefined') { //exports
    exports.smf = SecureMyFiles;
  } else if (typeof define === 'function' && define.amd) { //AMD
    define('smf', [], function () {
      return SecureMyFiles;
    });
  } else {
    root.smf = SecureMyFiles; //global 
  }
})(this);