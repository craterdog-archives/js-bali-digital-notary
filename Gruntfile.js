'use strict';

// wrapper function for grunt configuration
module.exports = function(grunt) {

  grunt.initConfig({

    // read in the package information
    pkg: grunt.file.readJSON('package.json'),

    // grunt-contrib-jshint plugin configuration (lint for JS)
    jshint: {
      files: [
        'Gruntfile.js',
        'src/**/*.js',
        'test/*.js'
      ],
      options: {
        node: true
      }
    },

    // grunt-contrib-clean plugin configuration (clean up files)
    clean: {
      build: [
        'dist/*',
        'test/config/'
      ],
      options: {
        force: false
      }
    },

    // grunt-mocha-test plugin configuration (unit testing)
    mochaTest: {
      test: {
        options: {
          reporter: 'spec',
          timeout: 10000 
        },
        src: ['test/*.js']
      }
    },

    // grunt-contrib-concat plugin configuration (file concatenation)
    concat: {
      options: {
        separator: '\n'
      },
      dist: {
        // concatenate the source files and place the result in destination
        src: [
          'src/**/*.js'
        ],
        dest: 'dist/<%= pkg.name %>.js'
      }
    },

    // grunt-contrib-uglify plugin configuration (removes whitespace)
    uglify: {
      options: {
        banner: '/*! <%= pkg.name %> <%= grunt.template.today("yyyy-mm-dd") %> */\n'
      },
      dist: {
        files: {
          'dist/<%= pkg.name %>.min.js': ['<%= concat.dist.dest %>']
        }
      }
    }

  });

  grunt.loadNpmTasks('grunt-contrib-clean');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-contrib-uglify');

  grunt.registerTask('build', 'Build the library.', ['clean:build', 'jshint', 'mochaTest', 'concat', 'uglify']);
  grunt.registerTask('default', 'The default task.', ['build']);

};
