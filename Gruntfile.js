module.exports = function (grunt) {

    // Project configuration.
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        jshint: {
            build: [
                'src/app.js', 'src/encrypt.js', 'src/storagemgr.js', 'src/utils.js'
            ]
        },
        concat: {
            build: {
                src: ['src/init.js', 'src/encryptor.js', 'src/enc-aescbc.js','src/storagemgr.js', 'src/utils.js', 'src/app.js'],
                dest: 'build/temp.js'
            },
            wrap: {
                src: 'src/wrap.js',
                dest: 'build/securemyfiles.js'
            }
        },
        indent: {
            build: {
                src: ['build/temp.js'],
                dest: 'build/temp.js',
                options: {
                    style: 'space',
                    size: 2,
                    change: 1
                }
            }
        },
        insert: {
            build: {
                src: 'build/temp.js',
                dest: 'build/securemyfiles.js',
                match: '  //Code goes here'
            }
        },
        clean: {
            build: {
                src: 'build/temp.js'
            }
        },
        uglify: {
            build: {
                src: 'build/securemyfiles.js',
                dest: 'build/securemyfiles.min.js'
            }
        }
    });

    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-indent');
    grunt.loadNpmTasks('grunt-insert');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-contrib-uglify');

    grunt.registerTask('default', ['jshint', 'concat', 'indent', 'insert', 'clean', 'uglify']);
};