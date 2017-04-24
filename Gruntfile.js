module.exports = function (grunt) {

    // Project configuration.
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        jshint: {
            dist: [
                './securemyfiles.js',
                'src/*.js'
            ],
            options: {
                reporterOutput: ''
            }
        },
        browserify: {
            smf: {
                files: {
                    'dist/securemyfiles.js': [
                        './securemyfiles.browserify.js'
                    ]
                }
            }
        },
        uglify: {
            dist: {
                src: 'dist/securemyfiles.js',
                dest: 'dist/securemyfiles.min.js'
            }
        }
    });

    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-browserify');
    grunt.loadNpmTasks('grunt-contrib-uglify');

    grunt.registerTask('default', ['jshint', 'browserify', 'uglify']);
};