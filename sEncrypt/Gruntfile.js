module.exports = function (grunt) {

    // Project configuration.
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        jshint: {
            dist: [
                'sEncrypt.js',
                'src/*.js'
            ],
            options: {
                reporterOutput: ''
            }
        },
        browserify: {
            sEncrypt: {
                files: {
                    'dist/sEncrypt.js': [
                        'sEncrypt.browserify.js'
                    ]
                }
            }
        },
        uglify: {
            dist: {
                src: 'dist/sEncrypt.js',
                dest: 'dist/sEncrypt.min.js'
            }
        }
    });

    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-browserify');
    grunt.loadNpmTasks('grunt-contrib-uglify');

    grunt.registerTask('default', ['jshint', 'browserify', 'uglify']);
};