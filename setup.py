from setuptools import setup, find_packages 
  
with open('requirements.txt') as f: 
    requirements = f.readlines() 
  
long_description = ''
  
setup( 
        name ='nx_tool', 
        version ='1.0.1', 
        author ='Rob Sitro', 
        author_email ='rsitro4@gmail.com', 
        description ='Command line tool to easily sync nexpose scan engines to their consoles', 
        long_description = long_description, 
        long_description_content_type ="text/markdown", 
        packages = find_packages(), 
        entry_points ={ 
            'console_scripts': [ 
                'nxtool = nx_tool.main:main'
            ] 
        }, 
        install_requires = requirements, 
        zip_safe = False
) 
